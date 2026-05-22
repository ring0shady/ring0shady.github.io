---
title: "120 Vulnerable Windows Drivers: A Defender's Field Guide to BYOVD, WDAC, and the Microsoft Driver Blocklist"
date: 2026-05-01 09:00:00 +0000
categories: [Defensive Research, BYOVD]
tags: [byovd, wdac, app-control, loldrivers, vulnerable-drivers, edr, detection-engineering, windows-kernel, blocklist, threat-intel]
pin: true
toc: true
description: >-
  A defensive, blue-team-first field guide to 120 vulnerable Windows drivers
  abused in Bring Your Own Vulnerable Driver attacks — organised for WDAC /
  App Control authors, SOC analysts, and incident responders. No exploit
  chains, no IOCTL codes, no bypass recipes. Just inventory, signing,
  blocklist, and detection guidance you can act on.
---

> **Editorial boundary.** This post is written for **defenders**. It contains
> **no** exploit chains, IOCTL values, kernel offsets, code, or step-by-step
> EDR-bypass procedures. "Detection" here means *defensive coverage status* —
> blocklist inclusion, LOLDrivers presence, CVE / KEV status, vendor
> reporting, and the telemetry that lets you see driver abuse — not a guide to
> evading EDR. Reverse engineering is treated as a **safe lab workflow**
> (metadata triage, signer verification, capability clustering, responsible
> disclosure) — not a procedural attack walkthrough.


## Executive summary

Bring Your Own Vulnerable Driver (BYOVD) is the Windows-kernel attack pattern
in which an adversary with local administrative access drops a legitimately
signed but internally flawed kernel driver, loads it, and then uses the
driver's weaknesses to operate at ring-0 — disabling EDR callbacks, killing
protected processes, dumping credentials, or wiping disks. Because the driver
carries a valid Authenticode signature, it bypasses Driver Signature
Enforcement out of the box ([MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/);
[ESET WeLiveSecurity, 2022](https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/)).

The technique that used to belong to nation-state operators (Turla, Slingshot,
Equation, Lazarus) is now standard tradecraft for commodity ransomware
families and dedicated "EDR killer" tools. ESET's 2026 research catalogued
**almost 90 EDR killers, 54 of them BYOVD-based, abusing 35 different
vulnerable drivers** — most aimed at terminating protected processes or
ripping out kernel callbacks used by security products ([ESET
WeLiveSecurity, 2026](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/)).
Huntress, writing in May 2026, calls BYOVD "the gold-standard EDR-impairment
method" in current incident response ([Huntress,
2026](https://www.huntress.com/blog/how-attackers-disable-av-edr)).

This post is the field guide to a **120-driver inventory** we built for blue
teams that need to operationalise that risk. The full dataset is shipped as
an Excel workbook, a machine-readable JSON, and a Jekyll `_data/` file used
to render the tables you will see below. Every claim is cited inline, and
nothing on the page is operationally weaponisable.

The dataset has three numbers worth keeping in mind:

| Metric | Value |
|---|---:|
| Total vulnerable Windows drivers catalogued | **120** |
| Rows with at least one assigned CVE | **16** |
| Rows with legitimate code-signing metadata | **120** |
| **P1 — block / verify now** | **34** |
| **P2 — block after testing** | **86** |

Source: workbook `Dashboard` sheet, generated from the LOLDrivers JSON corpus
([LOLDrivers API](https://www.loldrivers.io/api/drivers.json)) and curated
against vendor research. CVE coverage is intentionally low because **most
BYOVD-relevant drivers are abused via unsafe interfaces rather than CVEs** —
this is the central asymmetry that breaks naive CVE-only blocking.

## How to read this post

The 120-row table is rendered downstream of a small set of **decisions you
have to make as a defender** — not as a "list of bad files." The post is
organised in that order:

1. **BYOVD threat model.** What problem you are actually defending against.
2. **Methodology.** How the 120 rows were derived and what each column means.
3. **Top-priority drivers.** The P1 / high-risk subset, in a readable table.
4. **Detection coverage matrix.** Where each blocking, hunting, and audit
   surface actually lives.
5. **Safe reverse-engineering workflow.** What blue teams can do with a
   suspect driver without writing exploit code.
6. **WDAC / App Control blocklisting playbook.** From audit-mode to
   enforcement, with the operational caveats Microsoft itself flags.
7. **Hunting guidance.** Telemetry sources and detection patterns at a safe
   level — what to look for, not how to evade.
8. **Limitations and follow-ups.**
9. **Resources and citations.**

If you just want the data, jump to Resources section below.

## 1 · BYOVD threat model

BYOVD is not a vulnerability in Windows. It is the **economic exploitation of
the signed-driver ecosystem**: a defender has to trust a kernel signer until
proven otherwise; an attacker only has to find one signed driver whose
exposed IOCTL surface — or whose unsafe but legitimately privileged
functionality — gives them what they need.

### What BYOVD lets an attacker do (at a defensive level of detail)

Public defensive reporting consistently describes the same three high-level
outcomes from a successful BYOVD load, all observed in real intrusions:

- **Security-control tampering.** Disabling EDR sensors by removing kernel
  callbacks the EDR depends on, or by stripping protection from agent
  processes. Trellix's analysis of the Avast `aswArPot.sys` abuse and Sophos's
  Terminator / AuKill reporting both describe this outcome ([Trellix,
  2024](https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/);
  [Sophos AuKill,
  2023](https://www.sophos.com/en-us/blog/aukill-edr-killer-malware-abuses-process-explorer-driver);
  [Sophos Terminator,
  2024](https://www.sophos.com/en-us/blog/itll-be-back-attackers-still-abusing-terminator-tool-and-variants)).
- **Kernel-assisted process control or termination.** Forcibly killing
  protected processes (PPL) or terminating the agent service itself —
  observed across BlackByte, AvosLocker, Cuba, Akira, RansomHub, Embargo,
  Qilin, and Warlock campaigns ([Cisco Talos,
  2024](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/);
  [CrowdStrike,
  2024](https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/);
  [ESET Embargo,
  2024](https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/)).
- **Memory mapping, firmware, or destructive primitives.** Direct disk /
  firmware writes — used historically by HermeticWiper (`empntdrv.sys`),
  Shamoon (`elrawdsk.sys`), and ransomware abusing `BioNTdrv.sys` from
  Paragon Partition Manager ([SentinelOne HermeticWiper,
  2022](https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/);
  [CERT/CC VU#726882,
  2025](https://kb.cert.org/vuls/id/726882)).

We catalogue these outcomes as **abuse categories**, not as exploitation
recipes. This is also the boundary we maintain in the workbook's *Read Me*
sheet and in our methodology brief.

### Why CVE-only thinking fails

Of the 120 rows in our dataset, **only 16 have a publicly assigned CVE**.
That ratio is not noise; it is structural. Vulnerable-driver behavior is
often **"working as designed"** — the driver exposes a privileged interface
without proper access checks, but the vendor never filed a CVE because the
behavior is not, strictly speaking, a memory-safety bug. Microsoft makes the
same point in its own blocklist guidance: the list targets drivers with
"known security vulnerabilities, … have been used by attackers to bypass the
Windows security model, or … exhibit malicious behaviors" ([Microsoft
recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)).

Practical consequence: **you cannot defend against BYOVD with a CVE feed
alone**. Your blocking and hunting surface has to operate on filename,
signer, hash, version, and observed behavior — not just CVE state.

## 2 · Methodology

The 120-row inventory aggregates the public **LOLDrivers** machine-readable
corpus by driver filename, then enriches each row with manufacturer, product,
version, CVE, signing, hash, source, and a defensive-priority assessment
([LOLDrivers about](https://www.loldrivers.io/about/);
[`drivers.json` API](https://www.loldrivers.io/api/drivers.json)).

The workbook ships four sheets:

- **Read Me** — usage guidance and safety boundary.
- **Driver Database** — sortable 120-row table.
- **Dashboard** — formula-driven counts (priority, abuse, signing, CVE).
- **Source Notes** — source descriptions, limitations, operational caveats.

Each row carries the following defensively-relevant fields (downloadable in
full as `byovd_vulnerable_windows_drivers_database.xlsx` from the
Resources section below):

| Column | What it means defensively |
|---|---|
| `filename` | Driver image filename — your **primary inventory key**. |
| `manufacturer` / `product` | Helps you correlate against software-asset inventory and business owners. |
| `versions` | Known vulnerable versions reported in the corpus / vendor advisories. |
| `cves` | Public CVE identifiers — when one exists. |
| `category` / `abuse_category` | High-level defensive class (security-control tampering, kernel-assisted process control, memory-mapping abuse). |
| `signing` / `cert_signer` | Sample-metadata signing assessment; **not** a safety judgment. |
| `loldrivers_verified` | Whether the row appears in the LOLDrivers corpus. |
| `sample_count` | Number of distinct sample hashes the corpus carries for this filename. |
| `sources` | Authoritative URLs — LOLDrivers, Microsoft blocklist, NVD, vendor blogs. |
| `wdac_action` | Recommended App Control / blocklist action — always begins with audit mode. |
| `risk_score` | 1–10 priority weight derived from sample count, CVE presence, signing, and reported abuse. |
| `priority` | P1 / P2 bucket used in this post. |
| `sha256_examples` | Up to three example SHA256s for blocklist authoring; **not** an exhaustive list. |

The **abuse-category vocabulary** comes from public defensive reporting and
intentionally **excludes** any operational detail (no IOCTL values, offsets,
or technique sequences). Categories are: *security-control tampering / EDR
process or service disabling*; *kernel-assisted process control or
termination*; *physical or kernel memory mapping abuse*; *arbitrary kernel
read/write primitive*; *hardware or I/O control abuse*; *CVE-driven kernel
privilege escalation*.

Three structural caveats apply to **every row** and should be carried into
any blocklist work you do downstream:

- **CVE coverage is incomplete by design** — many BYOVD-relevant drivers
  have no CVE because their behavior is "working as designed" but
  inadequately access-controlled.
- **"Legitimately signed" ≠ "safe."** The signing column reflects sample
  metadata, not a safety claim. Multiple drivers in the table are abused
  precisely *because* their signatures are still trusted.
- **The workbook is a candidate list, not an enforcement list.** Hash,
  signer, version, business owner, load path, and dependency must be
  validated locally before enforcement. Microsoft is explicit that blocking
  drivers "could cause devices or software to malfunction, and in rare cases
  lead to blue screen errors" — and that the same blocklist update has
  already broken real third-party software (see §6 below) ([Microsoft
  recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)).

## 3 · The 120-driver inventory at a glance

### Priority distribution

The dashboard distribution is sharply skewed toward **P2 — block after
testing**, which is the right shape: a small group of drivers (P1) have
strong public abuse signal and CVE backing; a long tail of P2 drivers have
LOLDrivers presence but lower individual signal and need local validation
before enforcement.

| Priority | Count | What it means |
|---|---:|---|
| P1 — block / verify now | 34 | Strong abuse signal: high sample count, public CVE, named-actor abuse, or Microsoft blocklist coverage. |
| P2 — block after testing | 86 | LOLDrivers-present; defensive coverage should be added after audit-mode validation in your environment. |
| P3 — inventory / monitor | 0 | Reserved for low-signal entries that we did not catalogue in this build. |

### Abuse-category distribution

Almost every entry in the dataset clusters into one defensive class — and
that single class is the dominant driver of BYOVD pain in 2024–2026:

| High-level abuse category | Count |
|---|---:|
| Security-control tampering / EDR process or service disabling | **118** |
| Kernel-assisted process control or termination | 1 |
| Physical or kernel memory mapping abuse | 1 |

This skew matches ESET's 2026 finding that the modern BYOVD market is
dominated by EDR-killing tooling ([ESET WeLiveSecurity,
2026](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/)).

### Top-priority (P1) drivers

The table below lists the **34 P1 entries**, sorted by risk score and sample
count. The full 120-row workbook (with hashes, signer DNs, full sources, and
version strings) is in `byovd_vulnerable_windows_drivers_database.xlsx` on
the Resources section below.

| # | Driver | Manufacturer | Product | CVEs | Risk | Samples | LOLDrivers |
|---:|---|---|---|---|---:|---:|:---:|
| 1 | `ElbyCDIO.sys` | Elaborate Bytes AG | CDRTools | CVE-2009-0824 | 10 | 42 | ✓ |
| 2 | `aswArPot.sys` | AVAST Software | Avast Antivirus | CVE-2022-26522; CVE-2022-26523 | 10 | 40 | ✓ |
| 3 | `nscm.sys` | Novell, Inc. | Novell XTier | CVE-2013-3956 | 10 | 39 | ✓ |
| 4 | `NICM.SYS` | Novell, Inc. | Novell XTier | CVE-2013-3956 | 10 | 22 | ✓ |
| 5 | `zam64.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | 10 | 9 | ✓ |
| 6 | `Afd.sys` | Microsoft Corporation | Microsoft® Windows® Operating System | CVE-2023-21768 | 9 | 2 | ✓ |
| 7 | `zamguard64.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | 9 | 2 | ✓ |
| 8 | `ACE-BASE.sys` | ANTICHEATEXPERT.COM | Anti-Cheat Expert | CVE-2024-22830 | 9 | 1 | – |
| 9 | `iqvw64e.sys` | Intel Corporation | Intel(R) iQVW64.SYS | CVE-2015-2291 | 9 | 1 | ✓ |
| 10 | `ncpl.sys` | Novell, Inc. | Novell XTier | CVE-2013-3956 | 9 | 1 | ✓ |
| 11 | `probmon.sys` | ITM SYSTEM | ITM SYSTEM File Filter Driver | CVE-2024-26506 | 9 | 1 | ✓ |
| 12 | `tProtect.dll` | Zmana Ltd. | ZAM | CVE-2018-5713 | 9 | 1 | ✓ |
| 13 | `wsftprm.sys` | Topaz OFD | wsddprm | CVE-2023-52271 | 9 | 1 | ✓ |
| 14 | `zamguard32.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | 9 | 1 | ✓ |
| 15 | `TmComm.sys` | Trend Micro Inc. | Trend Micro Eyes | N/A | 8 | 42 | ✓ |
| 16 | `RTCore64.sys` | N/A | N/A | N/A | 8 | 35 | ✓ |
| 17 | `procexp.Sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | 8 | 29 | ✓ |
| 18 | `netfilter2.sys` | Windows (R) Win 7 DDK provider | Windows (R) Win 7 DDK driver | N/A | 8 | 25 | ✓ |
| 19 | `IObitUnlocker.sys` | IObit | IObitUnlocker | N/A | 8 | 16 | ✓ |
| 20 | `gdrv.sys` | GIGA-BYTE TECHNOLOGY CO., LTD. | GIGA-BYTE Software driver | N/A | 8 | 13 | ✓ |
| 21 | `HWiNFO32.SYS` | REALiX(tm) | HWiNFO32 Kernel Driver | N/A | 8 | 11 | ✓ |
| 22 | `kEvP64.sys` | PowerTool | PowerTool | N/A | 8 | 9 | ✓ |
| 23 | `SANDRA` | SiSoftware | SiSoftware Sandra | N/A | 8 | 8 | ✓ |
| 24 | `mhyprot2.sys` | N/A | N/A | N/A | 8 | 8 | ✓ |
| 25 | `rtif.sys` | TenAsys Corporation | INtime | N/A | 8 | 7 | ✓ |
| 26 | `viragt.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | 8 | 7 | ✓ |
| 27 | `RadHwMgr.sys` | Radiant Systems, Inc. | Radiant Systems, Inc. Hardware Manager driver | N/A | 8 | 6 | ✓ |
| 28 | `PDFWKRNL.sys` | Advanced Micro Devices, Inc. | USB-C Power Delivery Firmware Update Utility Driver | N/A | 8 | 5 | ✓ |
| 29 | `CSAgent.sys` | CrowdStrike, Inc. | CrowdStrike Falcon Sensor | N/A | 8 | 4 | ✓ |
| 30 | `dbutil_2_3.sys` | N/A | N/A | N/A | 8 | 4 | ✓ |
| 31 | `ene.sys` | N/A | N/A | N/A | 8 | 4 | ✓ |
| 32 | `EneIo64.sys` | N/A | N/A | N/A | 8 | 3 | ✓ |
| 33 | `LgDataCatcher.sys` | Windows (R) Win 7 DDK provider | GameAcc | N/A | 8 | 3 | ✓ |
| 34 | `viragt64.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | 8 | 3 | ✓ |

Reading the table:

- **`aswArPot.sys` (Avast), `RTCore64.sys` (MSI), `gdrv.sys` (GIGABYTE),
  `zam64.sys` / `zamguard64.sys` (Zemana), `procexp.sys` (Sysinternals),
  `dbutil_2_3.sys` (Dell), `mhyprot2.sys` (miHoYo), `viragt64.sys` (TG Soft),
  `iqvw64e.sys` (Intel)** are the names you will see most often in
  ransomware and EDR-killer post-incident reporting from Cisco Talos, ESET,
  Sophos, CrowdStrike, Trellix, Trend Micro, and SentinelOne
  ([Talos, 2024](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/);
  [Trend Micro, 2022](https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html);
  [SentinelOne CVE-2021-21551](https://www.sentinelone.com/vulnerability-database/cve-2021-21551/)).
- **`CSAgent.sys`** appearing on the P1 list reflects LOLDrivers corpus
  presence and elevated risk weight from sample count, **not** a claim that
  the current shipping CrowdStrike Falcon sensor is exploitable; treat that
  row as an inventory and version-pinning trigger only and validate against
  vendor advisories before any policy change.
- **`Afd.sys`** (CVE-2023-21768) is a Microsoft-shipped driver and is a
  reminder that **first-party drivers also appear in this space** —
  blocking is not the appropriate response; **patching is** ([NVD
  CVE-2023-21768](https://nvd.nist.gov/vuln/detail/CVE-2023-21768)).

> **Treat the P1 list as a queue, not a verdict.** For each row, the
> defensive workflow is: confirm presence in your environment → pin
> manufacturer, version, signer, and hashes → check Microsoft blocklist and
> KEV coverage → run WDAC / App Control in **audit mode** → enforce if no
> business impact appears.


### The longer P2 tail

The 86 P2 entries cover hardware-vendor utilities (overclocking, BIOS-flash,
fan control, RGB), legacy security-product drivers, and a long tail of
specialist OEM software. They are exactly the drivers that an EDR-killer
author wants to test next: **signed, kernel-resident, and widely
distributed.** The full P2 list is embedded below so this Markdown file remains self-contained. Treat these rows as an audit-and-test queue rather than a lower-risk allowlist.

| # | Driver | Manufacturer | Product | CVEs | Risk | Samples | LOLDrivers |
|---:|---|---|---|---|---:|---:|:---:|
| 1 | `Rzpnk.sys` | Razer, Inc. | Rzpnk | CVE-2017-9769 | 7 | 22 | ✓ |
| 2 | `MsIo64.sys` | MICSYS Technology Co., LTd | MsIo64 Driver Version 1.3 | CVE-2020-17382 | 7 | 5 | ✓ |
| 3 | `BdApiUtil.sys` | Baidu, Inc. | Baidu Antivirus | N/A | 7 | 2 | ✓ |
| 4 | `DBUtilDrv2.sys` | Dell | DBUtil | N/A | 7 | 2 | ✓ |
| 5 | `HwRwDrv.sys` | Windows® winows 7 driver kits provider | Hardware read & write driver | N/A | 7 | 2 | ✓ |
| 6 | `LgDCatcher.sys` | NetFilterSDK.com | NetFilter SDK | N/A | 7 | 2 | ✓ |
| 7 | `ProxyDrv.sys` | 雷神（武汉）网络技术有限公司 | 雷神NN加速器 | N/A | 7 | 2 | ✓ |
| 8 | `Truesight` | Adlice Software | Truesight | N/A | 7 | 2 | ✓ |
| 9 | `VBoxTAP.sys` | innotek GmbH | VirtualBox Host Interface Networking Driver | N/A | 7 | 2 | ✓ |
| 10 | `WDTKernel.sys` | Dell Inc | WDTKernel.sys | N/A | 7 | 2 | ✓ |
| 11 | `amsdk.sys` | WatchDogDevelopment.com, LLC. | amsdk | N/A | 7 | 2 | ✓ |
| 12 | `mhyprot.sys` | N/A | N/A | N/A | 7 | 2 | ✓ |
| 13 | `wamsdk.sys` | WatchDogDevelopment.com, LLC. | wamsdk | N/A | 7 | 2 | ✓ |
| 14 | `05f8f514d1367aca856564af5443a75f47d22a30ce63f0b024a41e6b9553a527` | Palo Alto Networks, Inc. | Cortex XDR™ Advanced Endpoint Protection | N/A | 7 | 1 | ✓ |
| 15 | `26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e` | Kingsoft Corporation | Kingsoft Antivirus Security System | N/A | 7 | 1 | ✓ |
| 16 | `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428` | Baidu, Inc. | Baidu Antivirus | N/A | 7 | 1 | ✓ |
| 17 | `927e3aef03a8355d236230cace376b3023480a40c5ac08453c07dab343dd1f11` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 18 | `BS_HWMIO64_W10.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | 7 | 1 | ✓ |
| 19 | `BS_HWMIo64.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 20 | `BS_I2cIo.sys` | BIOSTAR Group | BIOSTAR I/O driver fle | N/A | 7 | 1 | ✓ |
| 21 | `BS_RCIO.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 22 | `BS_RCIO64.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | 7 | 1 | ✓ |
| 23 | `BS_RCIOW1064.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 24 | `BS_RVSIO64.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | 7 | 1 | ✓ |
| 25 | `BlackBoneDrv10.sys` | N/A | N/A | N/A | 7 | 1 | – |
| 26 | `BootRepair.sys` | LENOVO | BootRepair | N/A | 7 | 1 | ✓ |
| 27 | `CP2X72C` | Interface Corporation | GPC-2X72C | N/A | 7 | 1 | ✓ |
| 28 | `FoxKeDriver64.sys` | Foxconn (R) Corporation | Foxconn (R) Kernel Driver(64bit) | N/A | 7 | 1 | ✓ |
| 29 | `GGProtect64.sys` | 湖南南澳网络科技有限公司 | GG租号 | N/A | 7 | 1 | ✓ |
| 30 | `GoFly64.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 31 | `HWAuidoOs2Ec.sys` | Huawei Device Co., Ltd. | Huawei Audio Driver | N/A | 7 | 1 | ✓ |
| 32 | `HwOs2Ec10x64.sys` | Huawei | Huawei MateBook | N/A | 7 | 1 | ✓ |
| 33 | `HwOs2Ec7x64.sys` | Huawei | Huawei MateBook | N/A | 7 | 1 | ✓ |
| 34 | `KfeCo10X64.sys` | Rivet Networks, LLC. | Killer Traffic Control | N/A | 7 | 1 | ✓ |
| 35 | `KfeCo11X64.sys` | Rivet Networks, LLC. | Killer Traffic Control | N/A | 7 | 1 | ✓ |
| 36 | `PanMonFltX64.sys` | Pan Yazilim Bilisim Teknolojileri Tic. Ltd. Sti. | PanCafe Manager | N/A | 7 | 1 | – |
| 37 | `PoisonX.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 38 | `PoisonX10.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 39 | `PoisonX11.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 40 | `PoisonX12.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 41 | `PoisonX13.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 42 | `PoisonX14.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 43 | `PoisonX15.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 44 | `PoisonX16.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 45 | `PoisonX17.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 46 | `PoisonX18.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 47 | `PoisonX2.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 48 | `PoisonX3.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 49 | `PoisonX4.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 50 | `PoisonX5.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 51 | `PoisonX6.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 52 | `PoisonX7.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 53 | `PoisonX8.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 54 | `PoisonX9.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 55 | `RTSPER.SYS` | Realtek Semiconductor Corporation | Windows (R) Win 7 DDK driver | N/A | 7 | 1 | ✓ |
| 56 | `RTSUER.SYS` | Realsil Semiconductor Corporation | Windows (R) Win 7 DDK driver | N/A | 7 | 1 | ✓ |
| 57 | `STProcessMonitor.sys` | Safetica Technologies | Safetica | N/A | 7 | 1 | ✓ |
| 58 | `TPwSav.sys` | Compal Electronic, Inc. | IO Driver | N/A | 7 | 1 | ✓ |
| 59 | `TfSysMon.sys` | PC Tools | ThreatFire | N/A | 7 | 1 | – |
| 60 | `ViveRRAudio.sys` | HTC VIVE | VIVE Virtual Audio Driver | N/A | 7 | 1 | ✓ |
| 61 | `Windows-Memory-Informer.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 62 | `_xyzxbqvb.rdu_GFAC_Sys_x64.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 63 | `amdi2c.sys` | Advanced Micro Devices, Inc | AMD I2C Controller Driver | N/A | 7 | 1 | – |
| 64 | `amp.sys` | CYREN Inc. | CYREN AMP 5 | N/A | 7 | 1 | ✓ |
| 65 | `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` | K7 Computing Pvt. Ltd. | K7RKScan | N/A | 7 | 1 | ✓ |
| 66 | `chinese_cheat_driver.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 67 | `dcr.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 68 | `filnk.sys` | Filseclab Corporation | Filseclab Dynamic Defense System | N/A | 7 | 1 | ✓ |
| 69 | `jnprva.sys` | Pulse Secure, LLC | Secure Application Manager | N/A | 7 | 1 | ✓ |
| 70 | `kprocesshacker.sys` | wj32 | KProcessHacker | N/A | 7 | 1 | ✓ |
| 71 | `krpocesshacker.sys` | wj32 | KProcessHacker | N/A | 7 | 1 | ✓ |
| 72 | `l1malwarebits.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 73 | `mhyprot3.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 74 | `msrhook.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 75 | `nipalk.sys` | National Instruments Corporation | NI-PAL | N/A | 7 | 1 | ✓ |
| 76 | `p2KGhmzsARY1.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 77 | `procexp152.sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | 7 | 1 | ✓ |
| 78 | `procexp1627.sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | 7 | 1 | ✓ |
| 79 | `psmounterex.sys` | Windows (R) Win 7 DDK provider | PSMounterEx | N/A | 7 | 1 | ✓ |
| 80 | `sandra.sys` | SiSoftware | SiSoftware Sandra | N/A | 7 | 1 | ✓ |
| 81 | `signeddrv.sys` | N/A | N/A | N/A | 7 | 1 | ✓ |
| 82 | `superbmc.sys` | Super Micro Computer, Inc. | superbmc | N/A | 7 | 1 | ✓ |
| 83 | `szkg64.sys` | iS3 Inc. | Stopzilla | N/A | 7 | 1 | ✓ |
| 84 | `throttlestop.sys` | N/A | Low-Level Driver | N/A | 7 | 1 | ✓ |
| 85 | `viraglt64.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | 7 | 1 | ✓ |
| 86 | `wnbios.sys` | Windows (R) Win 7 DDK provider | Windows (R) Win 7 DDK driver | N/A | 7 | 1 | ✓ |

(All 86 P2 rows are shown above. The same data is also available in the downloadable workbook and compact JSON when this article is published with the accompanying assets.)

## Full 120-driver database

The table below is embedded directly in this Markdown file so the article is self-contained outside Jekyll. The **Defensive detection coverage** column does not claim whether a driver bypasses or evades a specific EDR; it summarizes public defensive coverage signals such as LOLDrivers verification, CVE mapping, code-signing metadata, and whether the row should be handled as P1 or P2 in a WDAC / App Control review.

| # | Driver | Manufacturer | Product / family | CVEs | Abuse category | Signing | Risk | Priority | Defensive detection coverage | Sources |
|---:|---|---|---|---|---|---|---:|---|---|---|
| 1 | `ElbyCDIO.sys` | Elaborate Bytes AG | CDRTools | CVE-2009-0824 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 10 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[media.kasperskycontenthub.com](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf) |
| 2 | `aswArPot.sys` | AVAST Software | Avast Antivirus | CVE-2022-26522; CVE-2022-26523 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 10 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 3 | `nscm.sys` | Novell, Inc. | Novell XTier | CVE-2013-3956 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 10 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 4 | `NICM.SYS` | Novell, Inc. | Novell XTier | CVE-2013-3956 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 10 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c) |
| 5 | `zam64.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 10 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [reddit.com](https://www.reddit.com/r/crowdstrike/comments/13wjrgn/20230531_situational_awareness_spyboy_defense/)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[Trend Micro](https://www.trendmicro.com/en_us/research/23/e/attack-on-security-titans-earth-longzhi-returns-with-new-tricks.html) |
| 6 | `Afd.sys` | Microsoft Corporation | Microsoft® Windows® Operating System | CVE-2023-21768 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [securityintelligence.com](https://securityintelligence.com/x-force/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock/)<br>[Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21768)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 7 | `zamguard64.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [reddit.com](https://www.reddit.com/r/crowdstrike/comments/13wjrgn/20230531_situational_awareness_spyboy_defense/)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[Trend Micro](https://www.trendmicro.com/en_us/research/23/e/attack-on-security-titans-earth-longzhi-returns-with-new-tricks.html) |
| 8 | `ACE-BASE.sys` | ANTICHEATEXPERT.COM | Anti-Cheat Expert | CVE-2024-22830 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | CVE-mapped; signed-driver risk; high-priority blocklist review | [LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 9 | `iqvw64e.sys` | Intel Corporation | Intel(R) iQVW64.SYS | CVE-2015-2291 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [CrowdStrike](https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/)<br>[expel.com](https://expel.com/blog/well-that-escalated-quickly-how-a-red-team-went-from-domain-user-to-kernel-memory/)<br>[github.com](https://github.com/Exploitables/CVE-2015-2291) |
| 10 | `ncpl.sys` | Novell, Inc. | Novell XTier | CVE-2013-3956 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 11 | `probmon.sys` | ITM SYSTEM | ITM SYSTEM File Filter Driver | CVE-2024-26506 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [ESET](https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 12 | `tProtect.dll` | Zmana Ltd. | ZAM | CVE-2018-5713 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [reddit.com](https://www.reddit.com/r/crowdstrike/comments/13wjrgn/20230531_situational_awareness_spyboy_defense/)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[Trend Micro](https://www.trendmicro.com/en_us/research/23/e/attack-on-security-titans-earth-longzhi-returns-with-new-tricks.html) |
| 13 | `wsftprm.sys` | Topaz OFD | wsddprm | CVE-2023-52271 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [northwave-cybersecurity.com](https://northwave-cybersecurity.com/vulnerability-notice-topaz-antifraud)<br>[github.com](https://github.com/xM0kht4r/AV-EDR-Killer)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 14 | `zamguard32.sys` | Zemana Ltd. | ZAM | CVE-2018-5713 | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 9 | P1 - Block/verify now | LOLDrivers verified; CVE-mapped; signed-driver risk; high-priority blocklist review | [reddit.com](https://www.reddit.com/r/crowdstrike/comments/13wjrgn/20230531_situational_awareness_spyboy_defense/)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[Trend Micro](https://www.trendmicro.com/en_us/research/23/e/attack-on-security-titans-earth-longzhi-returns-with-new-tricks.html) |
| 15 | `TmComm.sys` | Trend Micro Inc. | Trend Micro Eyes | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 16 | `RTCore64.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[Sophos](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/)<br>[github.com](https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/RTCore64_MSI_Afterburner_v.4.6.4.16117) |
| 17 | `procexp.Sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [malware.news](https://malware.news/t/lazarus-group-attack-case-using-vulnerability-of-certificate-software-commonly-used-by-public-institutions-and-universities/67715)<br>[waawaa.github.io](https://waawaa.github.io/en/Bypass-PPL-Using-Process-Explorer/)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/57) |
| 18 | `netfilter2.sys` | Windows (R) Win 7 DDK provider | Windows (R) Win 7 DDK driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 19 | `IObitUnlocker.sys` | IObit | IObitUnlocker | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 20 | `gdrv.sys` | GIGA-BYTE TECHNOLOGY CO., LTD. | GIGA-BYTE Software driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/hoangprod/DanSpecial)<br>[github.com](https://github.com/namazso/physmem_drivers)<br>[secureauth.com](https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities) |
| 21 | `HWiNFO32.SYS` | REALiX(tm) | HWiNFO32 Kernel Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 22 | `kEvP64.sys` | PowerTool | PowerTool | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 23 | `mhyprot2.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/namazso/physmem_drivers)<br>[github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/) |
| 24 | `SANDRA` | SiSoftware | SiSoftware Sandra | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 25 | `rtif.sys` | TenAsys Corporation | INtime | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [blogs.vmware.com](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 26 | `viragt.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 27 | `RadHwMgr.sys` | Radiant Systems, Inc. | Radiant Systems, Inc. Hardware Manager driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [blogs.vmware.com](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 28 | `PDFWKRNL.sys` | Advanced Micro Devices, Inc. | USB-C Power Delivery Firmware Update Utility Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained/)<br>[blogs.vmware.com](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 29 | `CSAgent.sys` | CrowdStrike, Inc. | CrowdStrike Falcon Sensor | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [elastic.co](https://www.elastic.co/security-labs/abyssworker)<br>[Sophos](https://news.sophos.com/en-us/2025/08/06/shared-secret-edr-killer-in-the-kill-chain/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 30 | `dbutil_2_3.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/namazso/physmem_drivers)<br>[sentinelone.com](https://www.sentinelone.com/labs/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 31 | `ene.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 32 | `EneIo64.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [gist.github.com](https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 33 | `LgDataCatcher.sys` | Windows (R) Win 7 DDK provider | GameAcc | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 34 | `viragt64.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 8 | P1 - Block/verify now | LOLDrivers verified; signed-driver risk; high-priority blocklist review | [github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 35 | `Rzpnk.sys` | Razer, Inc. | Rzpnk | CVE-2017-9769 | Kernel-assisted process control or termination | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; CVE-mapped; signed-driver risk; audit before enforcement | [github.com](https://github.com/nomi-sec/PoC-in-GitHub/blob/2a85c15ed806287861a7adec6545c85aec618e3b/2017/CVE-2017-9769.json#L13)<br>[Rapid7](https://www.rapid7.com/db/modules/exploit/windows/local/razer_zwopenprocess/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 36 | `MsIo64.sys` | MICSYS Technology Co., LTd | MsIo64 Driver Version 1.3 | CVE-2020-17382 | Physical or kernel memory mapping abuse | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; CVE-mapped; signed-driver risk; audit before enforcement | [matteomalvica.com](https://www.matteomalvica.com/blog/2020/09/24/weaponizing-cve-2020-17382/)<br>[packetstormsecurity.com](https://packetstormsecurity.com/files/159315/MSI-Ambient-Link-Driver-1.0.0.8-Privilege-Escalation.html)<br>[coresecurity.com](https://www.coresecurity.com/core-labs/advisories/msi-ambient-link-multiple-vulnerabilities) |
| 37 | `amsdk.sys` | WatchDogDevelopment.com, LLC. | amsdk | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [research.checkpoint.com](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/55#issuecomment-1537161951)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 38 | `BdApiUtil.sys` | Baidu, Inc. | Baidu Antivirus | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/231)<br>[github.com](https://github.com/RainbowDynamix/GoodBaiii)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/204) |
| 39 | `DBUtilDrv2.sys` | Dell | DBUtil | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/dell-driver-fix-still-allows-windows-kernel-level-attacks/) |
| 40 | `HwRwDrv.sys` | Windows® winows 7 driver kits provider | Hardware read & write driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained/)<br>[github.com](https://github.com/namazso/physmem_drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 41 | `LgDCatcher.sys` | NetFilterSDK.com | NetFilter SDK | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 42 | `mhyprot.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/namazso/physmem_drivers)<br>[github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/) |
| 43 | `ProxyDrv.sys` | 雷神（武汉）网络技术有限公司 | 雷神NN加速器 | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 44 | `Truesight` | Adlice Software | Truesight | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/ph4nt0mbyt3/Darkside)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 45 | `VBoxTAP.sys` | innotek GmbH | VirtualBox Host Interface Networking Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [gist.github.com](https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 46 | `wamsdk.sys` | WatchDogDevelopment.com, LLC. | wamsdk | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [research.checkpoint.com](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 47 | `WDTKernel.sys` | Dell Inc | WDTKernel.sys | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/290)<br>[blogs.vmware.com](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 48 | `05f8f514d1367aca856564af5443a75f47d22a30ce63f0b024a41e6b9553a527` | Palo Alto Networks, Inc. | Cortex XDR™ Advanced Endpoint Protection | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [Sophos](https://news.sophos.com/en-us/2025/08/06/shared-secret-edr-killer-in-the-kill-chain/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 49 | `26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e` | Kingsoft Corporation | Kingsoft Antivirus Security System | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/BlackSnufkin/BYOVD)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 50 | `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428` | Baidu, Inc. | Baidu Antivirus | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/BlackSnufkin/BYOVD)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 51 | `927e3aef03a8355d236230cace376b3023480a40c5ac08453c07dab343dd1f11` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [Sophos](https://news.sophos.com/en-us/2025/08/06/shared-secret-edr-killer-in-the-kill-chain/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 52 | `_xyzxbqvb.rdu_GFAC_Sys_x64.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 53 | `amdi2c.sys` | Advanced Micro Devices, Inc | AMD I2C Controller Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | signed-driver risk; audit before enforcement | [github.com](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 54 | `amp.sys` | CYREN Inc. | CYREN AMP 5 | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [gist.github.com](https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 55 | `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` | K7 Computing Pvt. Ltd. | K7RKScan | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/BlackSnufkin/BYOVD)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 56 | `BlackBoneDrv10.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | signed-driver risk; audit before enforcement | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 57 | `BootRepair.sys` | LENOVO | BootRepair | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/phantom-killer-reverse-engineering-and-weaponizing-a-lenovo-driver-to-terminate-edr-processes-9191cd06374f)<br>[github.com](https://github.com/redteamfortress/PhantomKiller)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 58 | `BS_HWMIo64.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 59 | `BS_HWMIO64_W10.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 60 | `BS_I2cIo.sys` | BIOSTAR Group | BIOSTAR I/O driver fle | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 61 | `BS_RCIO.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 62 | `BS_RCIO64.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[github.com](https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Biostar.yar#L54) |
| 63 | `BS_RCIOW1064.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 64 | `BS_RVSIO64.sys` | BIOSTAR Group | BIOSTAR I/O driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 65 | `chinese_cheat_driver.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 66 | `CP2X72C` | Interface Corporation | GPC-2X72C | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [blogs.vmware.com](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 67 | `dcr.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/wjcsharp/DriveCrypt)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 68 | `filnk.sys` | Filseclab Corporation | Filseclab Dynamic Defense System | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/zeze-zeze/WindowsKernelVuln/tree/master/CVE-2023-1444)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 69 | `FoxKeDriver64.sys` | Foxconn (R) Corporation | Foxconn (R) Kernel Driver(64bit) | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 70 | `GGProtect64.sys` | 湖南南澳网络科技有限公司 | GG租号 | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 71 | `GoFly64.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/299)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 72 | `HWAuidoOs2Ec.sys` | Huawei Device Co., Ltd. | Huawei Audio Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 73 | `HwOs2Ec10x64.sys` | Huawei | Huawei MateBook | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 74 | `HwOs2Ec7x64.sys` | Huawei | Huawei MateBook | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 75 | `jnprva.sys` | Pulse Secure, LLC | Secure Application Manager | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [northwave-cybersecurity.com](https://northwave-cybersecurity.com/ivanti-pulse-vpn-privilege-escalation)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 76 | `KfeCo10X64.sys` | Rivet Networks, LLC. | Killer Traffic Control | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [zwclose.github.io](https://zwclose.github.io/2023/04/18/killer2.html)<br>[twitter.com](https://twitter.com/zwclose/status/1648441215808049153)<br>[zwclose.github.io](https://zwclose.github.io/2022/12/18/killer1.html) |
| 77 | `KfeCo11X64.sys` | Rivet Networks, LLC. | Killer Traffic Control | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [zwclose.github.io](https://zwclose.github.io/2023/04/18/killer2.html)<br>[twitter.com](https://twitter.com/zwclose/status/1648441215808049153)<br>[zwclose.github.io](https://zwclose.github.io/2022/12/18/killer1.html) |
| 78 | `kprocesshacker.sys` | wj32 | KProcessHacker | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [unknowncheats.me](https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html)<br>[unknowncheats.me](https://www.unknowncheats.me/forum/anti-cheat-bypass/312791-bypaph-process-hackers-bypass-read-write-process-virtual-memory-kernel-mem.html#post2315763)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver) |
| 79 | `krpocesshacker.sys` | wj32 | KProcessHacker | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [unknowncheats.me](https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html)<br>[unknowncheats.me](https://www.unknowncheats.me/forum/anti-cheat-bypass/312791-bypaph-process-hackers-bypass-read-write-process-virtual-memory-kernel-mem.html#post2315763)<br>[github.com](https://github.com/elastic/protections-artifacts/search?q=VulnDriver) |
| 80 | `l1malwarebits.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 81 | `mhyprot3.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 82 | `msrhook.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/namazso/physmem_drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 83 | `nipalk.sys` | National Instruments Corporation | NI-PAL | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/303)<br>[ni.com](https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/improper-input-validation-in-ni-pal.html)<br>[NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-38304) |
| 84 | `p2KGhmzsARY1.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 85 | `PanMonFltX64.sys` | Pan Yazilim Bilisim Teknolojileri Tic. Ltd. Sti. | PanCafe Manager | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | signed-driver risk; audit before enforcement | [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 86 | `PoisonX.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 87 | `PoisonX10.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 88 | `PoisonX11.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 89 | `PoisonX12.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 90 | `PoisonX13.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 91 | `PoisonX14.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 92 | `PoisonX15.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 93 | `PoisonX16.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 94 | `PoisonX17.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 95 | `PoisonX18.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 96 | `PoisonX2.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 97 | `PoisonX3.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 98 | `PoisonX4.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 99 | `PoisonX5.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 100 | `PoisonX6.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 101 | `PoisonX7.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 102 | `PoisonX8.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 103 | `PoisonX9.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [medium.com](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)<br>[github.com](https://github.com/j3h4ck/PoisonKiller/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 104 | `procexp152.sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [malware.news](https://malware.news/t/lazarus-group-attack-case-using-vulnerability-of-certificate-software-commonly-used-by-public-institutions-and-universities/67715)<br>[waawaa.github.io](https://waawaa.github.io/en/Bypass-PPL-Using-Process-Explorer/)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/57) |
| 105 | `procexp1627.sys` | Sysinternals - www.sysinternals.com | Process Explorer | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [malware.news](https://malware.news/t/lazarus-group-attack-case-using-vulnerability-of-certificate-software-commonly-used-by-public-institutions-and-universities/67715)<br>[waawaa.github.io](https://waawaa.github.io/en/Bypass-PPL-Using-Process-Explorer/)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/57) |
| 106 | `psmounterex.sys` | Windows (R) Win 7 DDK provider | PSMounterEx | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [northwave-cybersecurity.com](https://northwave-cybersecurity.com/exploiting-enterprise-backup-software-for-privilege-escalation-part-one)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 107 | `RTSPER.SYS` | Realtek Semiconductor Corporation | Windows (R) Win 7 DDK driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [linkedin.com](https://www.linkedin.com/pulse/vulnerabilities-realtek-sd-card-reader-driver-part-1-myngerbayev-czqmf, https://github.com/zwclose/realteksd)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 108 | `RTSUER.SYS` | Realsil Semiconductor Corporation | Windows (R) Win 7 DDK driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [linkedin.com](https://www.linkedin.com/pulse/vulnerabilities-realtek-sd-card-reader-driver-part-1-myngerbayev-czqmf, https://github.com/zwclose/realteksd)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 109 | `sandra.sys` | SiSoftware | SiSoftware Sandra | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 110 | `signeddrv.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 111 | `STProcessMonitor.sys` | Safetica Technologies | Safetica | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [cve.org](https://www.cve.org/CVERecord?id=CVE-2025-70795)<br>[github.com](https://github.com/magicsword-io/LOLDrivers/issues/268)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 112 | `superbmc.sys` | Super Micro Computer, Inc. | superbmc | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 113 | `szkg64.sys` | iS3 Inc. | Stopzilla | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [greyhathacker.net](https://www.greyhathacker.net/?p=1025)<br>[decoder.cloud](https://decoder.cloud/2025/01/09/the-almost-forgotten-vulnerable-driver/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 114 | `TfSysMon.sys` | PC Tools | ThreatFire | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | signed-driver risk; audit before enforcement | [github.com](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 115 | `throttlestop.sys` | N/A | Low-Level Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [securelist.com](https://securelist.com/av-killer-exploiting-throttlestop-sys/117026/)<br>[cve.org](https://www.cve.org/CVERecord?id=CVE-2025-7771)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 116 | `TPwSav.sys` | Compal Electronic, Inc. | IO Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [blackpointcyber.com](https://blackpointcyber.com/resources/blog/qilin-ransomware-and-the-hidden-dangers-of-byovd/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 117 | `viraglt64.sys` | TG Soft S.a.s. | VirIT Agent System | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/jbaines-r7/dellicious)<br>[Rapid7](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 118 | `ViveRRAudio.sys` | HTC VIVE | VIVE Virtual Audio Driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [northwave-cybersecurity.com](https://northwave-cybersecurity.com/vive-vr-headset-kernel-driver-vulnerable-for-out-of-bounds-memory-read)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 119 | `Windows-Memory-Informer.sys` | N/A | N/A | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/magicsword-io/LOLDrivers/issues/325)<br>[github.com](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |
| 120 | `wnbios.sys` | Windows (R) Win 7 DDK provider | Windows (R) Win 7 DDK driver | N/A | Security-control tampering / EDR process or service disabling | Legitimately signed in sample metadata | 7 | P2 - Block after testing | LOLDrivers verified; signed-driver risk; audit before enforcement | [github.com](https://github.com/myzxcg/RealBlindingEDR/)<br>[LOLDrivers](https://www.loldrivers.io/api/drivers.json) |


## 4 · Detection coverage — where each surface lives

"Is this driver detected?" is the wrong question for BYOVD; the right
question is **"on which defensive surfaces is this driver covered?"**
because the answer is almost always *several, with different latencies and
different failure modes*. The matrix below is the way we read each row.

| Defensive surface | What it covers | What it does **not** cover | Authoritative reference |
|---|---|---|---|
| **Microsoft vulnerable-driver blocklist** (HVCI / App Control enforced) | A curated list of non-Microsoft drivers with known kernel-elevation vulnerabilities, malicious behaviour, or malware-signing certificates. On by default on Windows 11 22H2+ when HVCI / Smart App Control are on. | Drivers added after your current cumulative-update level; blocklist updates ship via Windows Update. | [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules); [KB5020779](https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcfbc6a09936) |
| **Custom WDAC / App Control deny policy** | Your own driver-block list — hash, signer, file-attribute, or signer-chain rules under your control. | Drivers loaded before policy takes effect on legacy OS without HVCI; user-mode tooling that drops the driver before policy refresh. | [App Control deployment guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) |
| **LOLDrivers corpus** | Community-curated catalogue (filename, hash, signer, CVEs, references) — the source of our 120-row inventory. | Drivers not yet contributed to the corpus; pre-release / OEM-only drivers. | [LOLDrivers about](https://www.loldrivers.io/about/) |
| **NVD / CISA KEV** | Public CVE state and whether a CVE is known-exploited in the wild. | Drivers abused without a CVE (the 104-of-120 majority in our dataset). | [NVD](https://nvd.nist.gov); [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **ASR — "Block abuse of exploited vulnerable signed drivers"** | Attack-surface-reduction rule that prevents an application from *writing* a vulnerable signed driver to disk. | Drivers already resident; drivers dropped by trusted installer paths excluded from ASR scope. | [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) |
| **EDR / XDR driver-load telemetry** | Sysmon Event ID 6 (driver load), Windows Event IDs 7045 (service install) and 219 (driver fail), plus vendor-specific kernel-driver telemetry. | Loads that occur before sensor initialisation or after sensor tampering. | [Cisco Talos, 2024](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/); [Splunk Threat Research](https://www.splunk.com/en_us/blog/security/these-are-the-drivers-you-are-looking-for-detect-and-prevent-malicious-drivers.html) |
| **Sigma / YARA community rules** | Open detection content covering known vulnerable-driver filenames, service installs, and hash matches. | Polymorphic variants and re-signed copies (cf. the TrueSight 2,500-variant case) ([Security.com](https://www.security.com/threat-intelligence/ransomware-attacks-exploits)). | [LOLDrivers detections](https://www.loldrivers.io) |

Three pragmatic reads of the matrix:

- **HVCI is the single highest-leverage control.** It enforces the Microsoft
  blocklist and prevents unsigned kernel code execution; it is on by default
  on most new Windows 11 devices. If you only do one thing this quarter, do
  this ([Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)).
- **Blocklist coverage moves.** Microsoft has continued to extend the
  vulnerable-driver blocklist into 2026 — Ghacks reported in May 2026 that
  the April 2026 Windows update added `psmounterex.sys` (CVE-2023-43896) to
  the blocklist and **broke third-party backup software in the process**
  ([Ghacks, 2026](https://www.ghacks.net/2026/05/05/april-2026-windows-update-breaks-third-party-backup-software-by-blocking-vulnerable-driver/)).
  Tracking blocklist deltas is now a real change-management task.
- **EDR telemetry is necessary but not sufficient.** BYOVD's first job is
  often to disable the EDR. Sysmon-based driver-load monitoring sitting in a
  separate trust domain (SIEM, not endpoint) is the redundancy you want
  ([Splunk Threat Research](https://www.splunk.com/en_us/blog/security/these-are-the-drivers-you-are-looking-for-detect-and-prevent-malicious-drivers.html);
  [Huntress, 2026](https://www.huntress.com/blog/how-attackers-disable-av-edr)).

We deliberately avoid claims like "*driver X bypasses EDR Y*" unless that
claim is in primary defensive reporting (e.g. Huntress's February 2026
EnCase BYOVD case-study) and phrased the way the source phrases it
([Huntress EnCase BYOVD, 2026](https://www.huntress.com/blog/encase-byovd-edr-killer)).

## 5 · Safe reverse-engineering workflow

A blue-team RE pass on a suspect driver should answer five questions, in
order, and **stop at "yes — escalate"** rather than reproducing kernel
behaviour:

1. **What is it, in metadata terms?** File version info, product / company
   strings, internal name, original filename, build timestamp, signer DN,
   countersigner, and PE characteristics. Use `signtool`, `Get-AuthenticodeSignature`,
   or `osslsigncode` for the signature; `dumpbin /headers` or any standard
   PE parser for the rest.
2. **Is the signature still trusted?** Compare the embedded signer DN
   against the [Microsoft revoked / blocked driver list](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
   and against any internal CA / EKU policy you maintain. Revocation status
   can change after first publication; re-check.
3. **What does the import / export / strings surface look like?** Imports
   (`ntoskrnl.exe` calls to memory-mapping, MSR, or process-handle APIs),
   exports, embedded strings (service names, IOCTL names — only at the
   level of *categories*, not values), and any device-name strings used by
   the service. This is purely *static, capability-clustering* work.
4. **Has anyone already done this?** Cross-reference the SHA256 against
   LOLDrivers, VirusTotal, MalwareBazaar, the Microsoft blocklist, and
   vendor disclosure pages **before** spending lab time. The answer is
   often "yes" with a CVE attached.
5. **Does the driver match a documented abuse class?** Map your findings to
   the high-level categories in §2 — *security-control tampering*,
   *kernel-assisted process control*, *memory mapping*, *MSR R/W*,
   *DSE-related abuse*, *firmware / flash abuse*, *insufficient access
   control*. **Stop here.** If the answer is yes, escalate to vendor
   reporting and to your WDAC / blocklist authoring workflow; do not write
   or test exploit code against production assets.

If lab-only validation is needed, isolate it: dedicated VM, no network, no
production identity, snapshot rollback, and a written scope. Hand the result
to the vendor through [Microsoft's Driver Submission
form](https://www.microsoft.com/en-us/wdsi/driversubmission) and / or
through the vendor's PSIRT. Responsible disclosure is the deliverable, not
a working PoC.

We do **not** publish IOCTL values, kernel offsets, or any procedural
exploitation detail on this site. Where third-party research has published
those at a CVE level, we cite the CVE record itself
([NVD](https://nvd.nist.gov)) and the vendor advisory, and we let the reader
go there if they have a legitimate vulnerability-research need.

## 6 · WDAC / App Control blocklisting playbook

This is the operational sequence we recommend to teams using this dataset to
drive App Control work, derived from Microsoft's own guidance and the
"audit-first, enforce-later" pattern Microsoft repeatedly emphasises
([Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules);
[KB5020779](https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcfbc6a09936)):

1. **Turn on the Microsoft vulnerable-driver blocklist.** Confirm HVCI /
   Memory Integrity is on (Windows Security → Device Security → Core
   isolation) and Smart App Control / blocklist status is enforcing on
   Windows 11 22H2+. For earlier OS, deploy via App Control for Business
   policy.
2. **Layer your own deny policy on top.** Start from Microsoft's
   recommended driver block-rules XML (`SiPolicy.p7b`), add your own deny
   rules for filenames, SHA256 hashes, and signer DNs derived from the P1
   subset of this workbook.
3. **Deploy in audit mode first.** Run the policy in audit-only mode for at
   least one full patch cycle and one full backup / imaging cycle. Audit
   events go to **Microsoft-Windows-CodeIntegrity/Operational** (Event IDs
   3076 / 3077).
4. **Triage audit events against business owners.** Any driver flagged in
   audit needs an owner mapping before it can move to enforcement. This is
   where the workbook's *manufacturer* / *product* columns earn their keep.
5. **Add ASR coverage in parallel.** The Defender ASR rule "Block abuse of
   exploited vulnerable signed drivers" prevents apps from writing a
   vulnerable signed driver to disk — useful as a complementary control,
   not a replacement ([Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)).
6. **Promote to enforcement progressively.** Pilot ring → broad ring →
   estate. Keep a documented rollback path; Microsoft itself warns that
   blocking drivers "could cause devices or software to malfunction."
7. **Track blocklist deltas as a change-management task.** Subscribe to the
   blocklist documentation page and the Windows release health feed;
   record each delta and re-validate against business-critical software.
   The April 2026 `psmounterex.sys` incident is the canonical example of
   what happens when this step is skipped ([Ghacks,
   2026](https://www.ghacks.net/2026/05/05/april-2026-windows-update-breaks-third-party-backup-software-by-blocking-vulnerable-driver/)).
8. **Feed new findings back.** When you find a vulnerable driver in your
   estate that is not yet in the Microsoft blocklist, submit it via the
   [Microsoft Security Intelligence Driver Submission
   page](https://www.microsoft.com/en-us/wdsi/driversubmission).

> **Do not skip audit mode.** Microsoft's guidance is explicit and the
> field history is clear: enforcing a driver blocklist without an audit
> window risks bricking endpoints and breaking backup / imaging tooling.


## 7 · Hunting and telemetry (safe level)

The four telemetry sources below are the **minimum** detection surface for
BYOVD activity. None of them is a complete answer on its own; together they
give the SOC a chance to catch an EDR-impairment attempt **before** the EDR
is impaired.

| Telemetry | What to look for |
|---|---|
| **Sysmon Event ID 6** (driver load) | New / unusual driver image-loaded events, especially from non-system paths (`%TEMP%`, `%APPDATA%`, user-writable directories), and signer / hash deltas. |
| **Windows Event ID 7045** (service install) | Newly installed kernel services. Correlate service name and image path against your dataset of filenames; many BYOVD families install with predictable service names. |
| **Windows Event ID 219** (driver load failure) | Failed kernel loads — often the visible side of HVCI / blocklist enforcement, also useful to spot probing. |
| **App Control / WDAC audit events** (3076 / 3077 in `Microsoft-Windows-CodeIntegrity/Operational`) | Drivers that *would* have been blocked under your policy. The richest signal during rollout. |

Cross-reference the workbook's `filename`, `sha256_examples`, and
`cert_signer` columns against these event streams. Splunk's threat-research
team has published a detailed write-up of this inventory-plus-monitoring
approach that goes further than we will here ([Splunk Threat
Research](https://www.splunk.com/en_us/blog/security/these-are-the-drivers-you-are-looking-for-detect-and-prevent-malicious-drivers.html)).

Hunting pseudocode (safe / illustrative — **not** a copy-paste detection
content):

```text
# Concept: surface new kernel-driver loads from user-writable paths
# whose filename, hash, or signer matches our BYOVD inventory.

events = sysmon.event_id(6) ∪ winlog.event_id(7045)
events = events
    .where(image_path startswith user_writable_root)
    .where(filename in BYOVD_INVENTORY.filenames
           OR sha256   in BYOVD_INVENTORY.sample_hashes
           OR signer   in BYOVD_INVENTORY.cert_signers)

alert(events, severity=high, route="DFIR")
```

This is intentionally written as **pseudocode against a defensive
inventory** — not as a working Sigma rule for a specific product. The
detection-engineering team should adapt it to their SIEM with proper
allowlists for legitimate vendor installer paths.

## 8 · Limitations

- **CVE coverage is partial.** 16 of 120 rows carry public CVEs; the rest
  are documented through vendor advisories or LOLDrivers corpus presence.
  This is the structural feature of the BYOVD space described in §1, not a
  defect of the dataset.
- **"Legitimately signed" reflects sample metadata only.** Revocation status
  can change between sample collection and the time you read this page —
  always re-check against the current Microsoft blocklist and the issuing CA.
- **Sample-count weight has a ceiling.** A driver with three published
  samples may still be devastating in your estate if it is broadly
  deployed; do not let low `sample_count` deprioritise a driver whose
  vendor product is on every workstation.
- **First-party drivers exist in the corpus.** `Afd.sys` is the obvious
  case — block-listing is not the answer there; patching is.
- **This is a corpus snapshot, not an enforcement list.** Validate every
  candidate against local telemetry before enforcement.

## 9 · Resources and citations

- Driver workbook (Excel, sortable, with Dashboard): [`byovd_vulnerable_windows_drivers_database.xlsx`](./assets/downloads/byovd_vulnerable_windows_drivers_database.xlsx)
- Methodology brief: [`byovd-vulnerable-windows-drivers.pplx.md`](/assets/downloads/byovd-vulnerable-windows-drivers.pplx.md)
- Long-form research report: [`byovd-vulnerable-driver-database.pplx.md`](/assets/downloads/byovd-vulnerable-driver-database.pplx.md)
- Machine-readable extract: [`assets/data/byovd_drivers.json`](./assets/data/byovd_drivers.json)

Primary sources cited above:

- [LOLDrivers project](https://www.loldrivers.io) — community-driven vulnerable-driver corpus.
- [LOLDrivers API (`drivers.json`)](https://www.loldrivers.io/api/drivers.json) — machine-readable feed.
- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) — official blocklist guidance.
- [KB5020779 — vulnerable-driver blocklist release notes](https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcfbc6a09936).
- [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- [NVD](https://nvd.nist.gov).
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/).
- [Cisco Talos — Exploring vulnerable Windows drivers (2024)](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/).
- [ESET WeLiveSecurity — EDR killers explained, beyond the drivers (2026)](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/).
- [ESET WeLiveSecurity — Signed kernel drivers: unguarded gateway to Windows' core (2022)](https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/).
- [Huntress — How attackers disable AV / EDR (May 2026)](https://www.huntress.com/blog/how-attackers-disable-av-edr).
- [Huntress — EnCase BYOVD EDR killer case study (Feb 2026)](https://www.huntress.com/blog/encase-byovd-edr-killer).
- [Sophos — AuKill EDR killer (2023)](https://www.sophos.com/en-us/blog/aukill-edr-killer-malware-abuses-process-explorer-driver).
- [Sophos — Terminator still being abused (2024)](https://www.sophos.com/en-us/blog/itll-be-back-attackers-still-abusing-terminator-tool-and-variants).
- [Trellix — When guardians become predators (2024)](https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/).
- [CrowdStrike — Falcon prevents vulnerable-driver attacks (2024)](https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/).
- [SentinelOne — HermeticWiper (2022)](https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/).
- [Trend Micro — Genshin Impact anti-cheat driver abuse (2022)](https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html).
- [Splunk Threat Research — Detect and prevent malicious drivers](https://www.splunk.com/en_us/blog/security/these-are-the-drivers-you-are-looking-for-detect-and-prevent-malicious-drivers.html).
- [Rapid7 — Driver-based attacks: past and present (2021)](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/).
- [CERT/CC VU#726882 — Paragon BioNTdrv.sys (2025)](https://kb.cert.org/vuls/id/726882).
- [Ghacks — April 2026 Windows update breaks backup software via blocklist](https://www.ghacks.net/2026/05/05/april-2026-windows-update-breaks-third-party-backup-software-by-blocking-vulnerable-driver/).

> *Kernel Watch is a defensive research blog. No exploitation code, IOCTL
> values, kernel offsets, or operational bypass procedures are published
> here. All CVEs and threat-actor attributions are sourced from publicly
> disclosed vendor and researcher reports.*

