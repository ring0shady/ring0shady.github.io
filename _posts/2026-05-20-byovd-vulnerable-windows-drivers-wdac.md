---
title: "120 Vulnerable Windows Drivers: A Defender's Field Guide to BYOVD, WDAC, and the Microsoft Driver Blocklist"
date: 2026-05-20 09:00:00 +0000
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
{: .prompt-warning }

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

If you just want the data, jump to [Resources]({% link _tabs/resources.md %}).

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
[Resources tab]({% link _tabs/resources.md %})):

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
the [Resources tab]({% link _tabs/resources.md %}).

<div class="table-wrapper" markdown="block">

| # | Driver | Manufacturer | Product | CVEs | Risk | Samples | LOLDrivers |
|---:|---|---|---|---|---:|---:|:---:|
{% assign drivers = site.data.byovd_drivers | where:"priority","P1 - Block/verify now" | sort: "risk_score" | reverse %}
{% for d in drivers %}| {{ forloop.index }} | `{{ d.filename }}` | {{ d.manufacturer }} | {{ d.product }} | {{ d.cves }} | {{ d.risk_score }} | {{ d.sample_count }} | {% if d.loldrivers_verified == "TRUE" %}✓{% else %}–{% endif %} |
{% endfor %}

</div>

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
{: .prompt-info }

### The longer P2 tail

The 86 P2 entries cover hardware-vendor utilities (overclocking, BIOS-flash,
fan control, RGB), legacy security-product drivers, and a long tail of
specialist OEM software. They are exactly the drivers that an EDR-killer
author wants to test next: **signed, kernel-resident, and widely
distributed.** The full P2 list is in the workbook; here is a representative
slice to show the *shape* of that tail (the rest sits at parity in
defensive treatment).

<div class="table-wrapper" markdown="block">

| # | Driver | Manufacturer | Product | Samples |
|---:|---|---|---|---:|
{% assign p2 = site.data.byovd_drivers | where:"priority","P2 - Block after testing" | sort: "sample_count" | reverse %}
{% for d in p2 limit:20 %}| {{ forloop.index }} | `{{ d.filename }}` | {{ d.manufacturer }} | {{ d.product }} | {{ d.sample_count }} |
{% endfor %}

</div>

(Twenty of 86. Full list in the [downloadable workbook](/assets/downloads/byovd_vulnerable_windows_drivers_database.xlsx)
and as compact JSON at [`/assets/data/byovd_drivers.json`](/assets/data/byovd_drivers.json).)

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
{: .prompt-danger }

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

- Driver workbook (Excel, sortable, with Dashboard): [`byovd_vulnerable_windows_drivers_database.xlsx`](/assets/downloads/byovd_vulnerable_windows_drivers_database.xlsx)
- Methodology brief: [`byovd-vulnerable-windows-drivers.pplx.md`](/assets/downloads/byovd-vulnerable-windows-drivers.pplx.md)
- Long-form research report: [`byovd-vulnerable-driver-database.pplx.md`](/assets/downloads/byovd-vulnerable-driver-database.pplx.md)
- Machine-readable extract: [`/assets/data/byovd_drivers.json`](/assets/data/byovd_drivers.json)

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
{: .prompt-tip }
