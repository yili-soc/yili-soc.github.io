---
layout: post
title: "Atomic T1059.001: PowerShell"
date: 2026-10-26 12:00:00 -0600
tags: [atomic red team, detection, Execution, Microsoft Defender for Endpoint, KQL]
excerpt: "Atomic tests 13 and 15 for T1059.001: what MDE alerted on, how I triaged it, and a detection."
series: home-lab
label: "T1059.001 · Execution"
---

**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell (Execution). Parent: [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

## The test

Atomic tests 13 and 15 use Red Canary's AtomicTestHarnesses (ATH) module to start a new PowerShell process that runs `Write-Host <guid>`. Test 13 passes the command in plain text with `-C`, test 15 Base64-encoded with `-E`.

**Reproduce:**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 13,15 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 13,15
```

**Clean up:**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 13,15 -Cleanup
```

---

## Did MDE alert?

Yes. Microsoft Defender for Endpoint (MDE) opened one Medium incident with three alerts: two "Suspicious WMI process creation" from EDR, and one "An active 'LsassDumper' hacktool in a PowerShell script was prevented from executing via AMSI" from Antivirus.

![Incident 7 in the queue: 'LsassDumper' detected on one endpoint, Medium, with one LsassDumper alert and two Suspicious WMI process creation alerts](/assets/images/atomic-t1059-001/incident-queue.png)

A test that prints a GUID has nothing to do with LSASS, so that alert was the first thing I wanted to explain.

---

## What shows up in the logs

### Where it started

The process tree starts with `explorer.exe` launching `powershell.exe` (PID 12520) at 7:36 AM. `DeviceLogonEvents` showed a local interactive logon and no remote logon before it.

Under that shell is a long list of "powershell.exe executed a script" events. That was too many to open one by one, so I moved to advanced hunting.

![The LsassDumper alert's process tree: the test 13 wrapper (PID 11864) followed by a long list of "powershell.exe executed a script" events](/assets/images/atomic-t1059-001/amsi-alert-script-events.png)

### Cutting the noise

```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","WmiPrvSE.exe","explorer.exe") or FileName in~ ("powershell.exe","pwsh.exe","hostname.exe","whoami.exe")
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| sort by Timestamp asc
```

![84 items returned](/assets/images/atomic-t1059-001/noise-84-rows.png)

Most of the 84 rows were `net accounts` (10) and `auditpol /get` (20), which looks like discovery. Their parent was a PowerShell process started by `senseir.exe`, running signed scripts from the Defender `DataCollection` folder. SenseIR is MDE's own automated investigation component, and this burst ran at 9:28 AM, about 45 minutes before the test.

Excluding `senseir.exe` as the parent, plus `conhost.exe` and `csc.exe`, left 48 rows with every `net` and `auditpol` line still there. `senseir.exe` is their grandparent, not their parent. Excluding the SenseIR PowerShell itself (PID 11284) and `ipconfig.exe` got it down to 16:

```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where InitiatingProcessFileName != "senseir.exe"   // pass 1
| where FileName !in~ ("conhost.exe","csc.exe")      // pass 1: 48 rows
| where InitiatingProcessFileName in~ ("powershell.exe","wmiprvse.exe","explorer.exe","cmd.exe")
| where InitiatingProcessId != 11284                 // pass 2: SenseIR's PowerShell
| where FileName !~ "ipconfig.exe"                   // pass 2: 16 rows
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| sort by Timestamp asc
```

![16 items returned](/assets/images/atomic-t1059-001/clean-16-rows.png)

In a saved query, use `InitiatingProcessParentFileName !~ "senseir.exe"` instead of the PID.

### Reading the 16 rows

In order:

- `hostname.exe` and `whoami.exe`, which Invoke-AtomicTest runs to log each run
- two PowerShell processes for the prereq check, which looks for the AtomicTestHarnesses module
- ATH's `Out-ATHPowerShellCommandLineParameter` wrapper, once per test
- the two test payloads

The payloads' parent is `wmiprvse.exe`, not the shell that ran the test. ATH's help text for `Out-ATHPowerShellCommandLineParameter` says `-Execute` starts the command "with the WMI Win32_Process Create method". That is what the two WMI alerts fired on, and MDE maps them to T1047 Windows Management Instrumentation.

### Decoding test 15

In CyberChef: `From Base64`, then `Decode text` with UTF-16LE (1200).

![CyberChef recipe From Base64 plus Decode text UTF-16LE, output Write-Host 1bf05df6-eff9-415a-9e65-d24194b110a9](/assets/images/atomic-t1059-001/cyberchef-decoded.png)

It is the same `Write-Host` as test 13 with a different GUID. MDE raised the same WMI alert for both tests, so encoding didn't change the verdict.

---

## The LsassDumper alert

None of the 16 processes touched LSASS. The alert was raised by an AMSI scan of script content, not by a process, so I searched `DeviceEvents`:

```kql
DeviceEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where ActionType has "Amsi" or ActionType has "ScriptContent" or ActionType == "AntivirusDetection"
| project Timestamp, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| sort by Timestamp asc
```

![Six AntivirusDetection rows for HackTool:PowerShell/LsassDumper.A!amsi, two naming the file DumpLSASS.ps1](/assets/images/atomic-t1059-001/amsi-dumplsass.png)

All six rows are `HackTool:PowerShell/LsassDumper.A!amsi`, and two name a file: `DumpLSASS.ps1`.

Searching that file name led to the AtomicTestHarnesses repo, where `Windows/TestHarnesses/T1003.001_DumpLSASS/DumpLSASS.ps1` defines `Invoke-ATHDumpLSASS`. ATH loads every script in its `TestHarnesses` folder on import, so the PowerShell tests loaded the LSASS dump code too, and AMSI blocked it. Several other harness scripts compile C# with `Add-Type` on load, which is where the `csc.exe` processes came from.

To check that the dump code never ran:

```kql
DeviceEvents
| where Timestamp > ago(1d)
| where DeviceName == "winlab-vm"
| where FileName =~ "lsass.exe"
| where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall")
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where DeviceName == "winlab-vm"
| where FileName endswith ".dmp" or FileName has "lsass"
```

Both came back empty. The alert name describes what Defender matched, LSASS dump code in a script. Nothing was dumped.

---

## Detection

MDE caught this on its own. My version targets the behavior behind the WMI alerts, whatever tool is used: a script interpreter started by WMI.

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName contains "wmi"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp desc
```

![The detection returning the two payload processes from tests 13 and 15](/assets/images/atomic-t1059-001/detection-wmi-parent.png)

It returned the two test payloads. It covers PowerShell (T1059.001) started through WMI ([T1047](https://attack.mitre.org/techniques/T1047/)).

---

## Tuning

- SCCM/ConfigMgr, monitoring agents and remote management scripts also start processes over WMI. Allowlist them by service account or command line.
- `contains "wmi"` also matches names like `wmic.exe`. For a scheduled rule, use `=~ "wmiprvse.exe"`.
- Add a command-line condition (encoded command, download cradle, hidden window) to cut the volume.

This only catches payloads on the command line. For `-File` or `IEX` on a downloaded script, advanced hunting doesn't keep the full script text, so you need Script Block Logging (4104) in Sentinel.

---

## Takeaways

The incident title pointed at credential theft and the raw process list looked like discovery. Neither was what happened, and both times one field gave it away: the grandparent of `net.exe`, and the file name in the AMSI event.

When excluding noise, exclude the whole subtree. Filtering on the parent alone left 30 rows of MDE's own activity.

---

## References

- [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [Red Canary AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [Microsoft Learn: Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft Learn: DeviceEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table)
