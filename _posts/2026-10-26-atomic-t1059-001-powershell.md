---
layout: post
title: "Atomic T1059.001: PowerShell"
date: 2026-10-26 12:00:00 -0600
tags: [atomic red team, detection, Execution, Microsoft Defender for Endpoint, KQL]
excerpt: "Atomic tests 13 and 15 for T1059.001: what MDE alerted on, how I triaged it, and a detection."
---

## What this technique is

Attackers use PowerShell to run commands and scripts on Windows. It is on every machine, and the command can be hidden in a Base64 `-EncodedCommand` argument.

**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell (Execution). Parent: [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

## The test

I ran Atomic tests 13 and 15. Both use Red Canary's AtomicTestHarnesses (ATH) PowerShell module to start a new PowerShell process with a one-line command:

- Test 13 passes the command in plain text with `-C` (`-Command`).
- Test 15 passes it Base64-encoded with `-E` (`-EncodedCommand`).

In both cases the command is `Write-Host <guid>`. Running the pair shows whether encoding alone changes what Defender does.

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

Yes. Microsoft Defender for Endpoint (MDE) opened a Medium incident titled "'LsassDumper' detected on one endpoint", with three alerts:

| Alert | Source | Cause |
|---|---|---|
| Suspicious WMI process creation (x2) | EDR, mapped to T1047 | The PowerShell process from each test was started by WMI |
| An active 'LsassDumper' hacktool in a PowerShell script was prevented from executing via AMSI | Antivirus | Explained below |

![Incident 7: three alerts, the WMI alert mapped to T1047, and the process tree ending in two powershell.exe processes under WmiPrvSE.exe](/assets/images/atomic-t1059-001/incident-wmi-tree.png)

A test that only prints a GUID has nothing to do with LSASS, so that alert was the first thing I wanted to explain.

---

## What shows up in the logs

### Where it started

The top of the tree is `explorer.exe` starting `powershell.exe` (PID 12520) at 7:36 AM, which is an interactive shell opened from the desktop. `DeviceLogonEvents` showed a local interactive logon and no RDP or other remote logon before it.

Under that shell, the alert's process tree is a long list of "powershell.exe executed a script" events.

![The LsassDumper alert's process tree: the test 13 wrapper (PID 11864) followed by a long list of "powershell.exe executed a script" events](/assets/images/atomic-t1059-001/amsi-alert-script-events.png)

Opening each one in the portal would take a long time, so I moved to advanced hunting and pulled every process started in that window.

### Cutting the noise

```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","WmiPrvSE.exe","explorer.exe") or FileName in~ ("powershell.exe","pwsh.exe","hostname.exe","whoami.exe")
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| sort by Timestamp asc
```

It returned 84 rows.

![84 rows, most of them net.exe accounts and auditpol.exe /get](/assets/images/atomic-t1059-001/noise-84-rows.png)

Most of them were `net accounts` (10 times) and `auditpol /get` (20 times). That looks like account and audit policy discovery. The parent says otherwise: a PowerShell process started by `senseir.exe`, running signed scripts from `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\` with `-ExecutionPolicy AllSigned`. SenseIR is MDE's own automated investigation and response component. This burst also ran at 9:28 AM, about 45 minutes before the test.

On the first pass I excluded processes whose parent was `senseir.exe`, and dropped `conhost.exe` and `csc.exe` (the C# compiler that PowerShell's `Add-Type` calls) by name. That gave 48 rows, and every `net` and `auditpol` line was still there. Their parent is the PowerShell that SenseIR started, so `senseir.exe` is the grandparent. Excluding by parent only removes one level of the tree.

On the second pass I also excluded those SenseIR PowerShell PIDs, plus `ipconfig.exe`. That left 16 rows.

![16 rows: the Invoke-AtomicTest calls, the two ATH wrappers, and the two payload processes under wmiprvse.exe](/assets/images/atomic-t1059-001/clean-16-rows.png)

PIDs are fine for one triage session but they change after a reboot. For a saved query, filter on the grandparent instead:

```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where InitiatingProcessFileName in~ ("powershell.exe","wmiprvse.exe","explorer.exe","cmd.exe")
| where InitiatingProcessParentFileName !~ "senseir.exe"
| where FileName !in~ ("conhost.exe","csc.exe","ipconfig.exe")
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| sort by Timestamp asc
```

### Reading the 16 rows

In order, the 16 rows are:

- `hostname.exe` and `whoami.exe`, which Invoke-AtomicTest runs to log each run
- two PowerShell processes for the prereq check, which looks for the AtomicTestHarnesses module
- ATH's `Out-ATHPowerShellCommandLineParameter` wrapper, once per test
- the two test payloads

The payloads are not children of the shell that ran the test. Their parent is `wmiprvse.exe`. ATH's own help text for `Out-ATHPowerShellCommandLineParameter` says that with `-Execute`, the command line is "spawned with the WMI Win32_Process Create method". That is what the two WMI alerts fired on, and why MDE mapped them to T1047 Windows Management Instrumentation. Malware uses WMI the same way to break the link between its script and the process it starts.

### Decoding test 15

In CyberChef I used `From Base64`, then `Decode text` with UTF-16LE (1200). PowerShell expects `-EncodedCommand` to be UTF-16LE, so `From Base64` alone leaves a null byte after every character.

![CyberChef recipe From Base64 plus Decode text UTF-16LE, output Write-Host 1bf05df6-eff9-415a-9e65-d24194b110a9](/assets/images/atomic-t1059-001/cyberchef-decoded.png)

The result is `Write-Host 1bf05df6-eff9-415a-9e65-d24194b110a9`, the same as test 13 apart from the GUID. MDE raised the same WMI alert for both tests, so the encoding made no difference to the verdict.

---

## The LsassDumper alert

None of the 16 processes touched LSASS, so the process table didn't explain the third alert. Its title ends with "prevented from executing via AMSI", so I read up on AMSI. Microsoft describes the Antimalware Scan Interface as an API that lets applications pass content to the installed antivirus for scanning, and since PowerShell 5.1 every script block PowerShell runs is passed to it. That means this alert came from scanning script content, not from a process starting, so I looked in `DeviceEvents` instead:

```kql
DeviceEvents
| where Timestamp > ago(6h)
| where DeviceName == "winlab-vm"
| where ActionType has "Amsi" or ActionType has "ScriptContent" or ActionType == "AntivirusDetection"
| project Timestamp, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| sort by Timestamp asc
```

![Six AntivirusDetection rows for HackTool:PowerShell/LsassDumper.A!amsi, two naming the file DumpLSASS.ps1](/assets/images/atomic-t1059-001/amsi-dumplsass.png)

Six `AntivirusDetection` rows, all `HackTool:PowerShell/LsassDumper.A!amsi`, and two of them name a file: `DumpLSASS.ps1`.

I searched for that file name and found it in Red Canary's AtomicTestHarnesses repository, the module both tests use: `Windows/TestHarnesses/T1003.001_DumpLSASS/DumpLSASS.ps1`, which defines `Invoke-ATHDumpLSASS`. The module's `.psm1` loads every script in its `TestHarnesses` folder when it is imported. So running a PowerShell test also loaded ATH's LSASS dump code, PowerShell passed it to AMSI, and Defender blocked it on the signature. Several other harness scripts compile C# with `Add-Type` when they load, which is where the `csc.exe` processes came from.

To make sure the dump code never ran, I checked for access to `lsass.exe` and for dump files:

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

Both came back empty.

So the alert name is accurate about what Defender matched: LSASS dump code in a PowerShell script. It doesn't mean anything was dumped. The code came in with the test module and was blocked before it ran.

---

## Detection

MDE caught this on its own. I wanted a detection that doesn't depend on the tool or a signature, so I wrote one for the behavior behind the two WMI alerts: a script interpreter started by WMI.

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName contains "wmi"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp desc
```

![The detection returning the two payload processes from tests 13 and 15](/assets/images/atomic-t1059-001/detection-wmi-parent.png)

It returned the two test payloads. It covers PowerShell (T1059.001) when it is started through WMI ([T1047](https://attack.mitre.org/techniques/T1047/)), which is how both tests ran.

---

## Tuning

- SCCM/ConfigMgr, monitoring agents and remote management scripts also start processes over WMI. Allowlist them by service account or known command line, not by device.
- `contains "wmi"` also matches other parents with "wmi" in the name, such as `wmic.exe`. For a scheduled rule I'd use `=~ "wmiprvse.exe"` so it only matches the WMI provider host.
- For an alert rule, add a command-line condition (encoded command, download cradle, hidden window) to keep the volume down.
- Don't key on "PowerShell ran" alone. Searching for the `Write-Host` payloads without the parent filter also returned PowerShell started by `compattelrunner.exe` (Windows compatibility telemetry).

This works because tests 13 and 15 put the payload on the command line. With `-File script.ps1` or `IEX` on a downloaded script, the command line shows very little and the real code is in the script block. Advanced hunting doesn't keep full script text (the `PowerShellCommand` events in `DeviceEvents` only record command names). For that you need Script Block Logging (event 4104) sent to Sentinel.

---

## Takeaways

The incident title pointed at credential theft, and the raw process list looked like discovery. Neither was what happened. Both times the answer was in a single field: the grandparent of `net.exe`, and the file name in the AMSI event.

When you exclude noise, exclude the whole subtree. Filtering on the parent alone left 30 lines of MDE's own activity in my results.

---

## References

- [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [Red Canary AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [Microsoft Learn: Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft Learn: PowerShell security features (AMSI support)](https://learn.microsoft.com/powershell/scripting/security/security-features)
- [Microsoft Learn: DeviceEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table)
